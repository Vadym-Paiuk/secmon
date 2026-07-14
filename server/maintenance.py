"""
SecMon Maintenance — щоденний скрипт обслуговування бази даних.

Реалізує "горизонт" ієрархічного методу зберігання:
  - Архівує оперативні події старші OPERATIONAL_HORIZON_H годин з effectiveness=0
  - Стискає (прибирає raw) аналітичні події старші ANALYTICAL_HORIZON_DAYS днів
  - Видаляє архів старший ARCHIVE_HORIZON_DAYS днів
  - Ніколи не чіпає події з effectiveness > 0 або прив'язані до alerts

Запуск вручну:  python maintenance.py
Автоматично:    додай у Windows Task Scheduler — раз на добу.
"""
import os
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_

from database import SessionLocal
from models import Event, EventArchive, Alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("secmon-maintenance")

# --- Горизонти зберігання ---
OPERATIONAL_HORIZON_H    = 72    # оперативний шар: 72 години
ANALYTICAL_HORIZON_DAYS  = 90   # аналітичний шар: 90 днів (потім прибирається raw)
ARCHIVE_HORIZON_DAYS     = 365  # архів: 1 рік, потім видаляється


def run_maintenance():
    db: Session = SessionLocal()
    now = datetime.now(timezone.utc)
    stats = {"archived": 0, "stripped": 0, "deleted_archive": 0}

    try:
        # 1. Архівуємо оперативні події старші горизонту без підтвердженої ефективності
        op_cutoff = now - timedelta(hours=OPERATIONAL_HORIZON_H)
        to_archive = db.query(Event).filter(
            and_(
                Event.layer == "operational",
                Event.ts < op_cutoff,
                Event.effectiveness == 0.0,
                Event.correlated_alert_id == None,
            )
        ).all()

        for ev in to_archive:
            archive_row = EventArchive(
                orig_id=ev.id,
                ts=ev.ts,
                node_id=ev.node_id,
                source=ev.source,
                severity=ev.severity,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                port=ev.port,
                action=ev.action,
            )
            db.add(archive_row)
            db.delete(ev)
            stats["archived"] += 1

        db.commit()
        log.info(f"Архівовано оперативних подій: {stats['archived']}")

        # 2. Аналітичні події старші ANALYTICAL_HORIZON_DAYS — прибираємо raw (стискаємо)
        an_cutoff = now - timedelta(days=ANALYTICAL_HORIZON_DAYS)
        old_analytical = db.query(Event).filter(
            and_(
                Event.layer == "analytical",
                Event.ts < an_cutoff,
                Event.raw != None,
            )
        ).all()

        for ev in old_analytical:
            ev.raw = None   # прибираємо сирі дані, лишаємо нормалізовані поля
            stats["stripped"] += 1

        db.commit()
        log.info(f"Стиснуто аналітичних подій (прибрано raw): {stats['stripped']}")

        # 3. Видаляємо дуже старий архів
        arch_cutoff = now - timedelta(days=ARCHIVE_HORIZON_DAYS)
        old_archive = db.query(EventArchive).filter(EventArchive.ts < arch_cutoff).all()
        for row in old_archive:
            db.delete(row)
            stats["deleted_archive"] += 1

        db.commit()
        log.info(f"Видалено з архіву: {stats['deleted_archive']}")

        # 4. Зведення
        total_operational = db.query(Event).filter(Event.layer == "operational").count()
        total_analytical  = db.query(Event).filter(Event.layer == "analytical").count()
        total_archive     = db.query(EventArchive).count()

        log.info(
            f"Стан після обслуговування → "
            f"operational: {total_operational}, "
            f"analytical: {total_analytical}, "
            f"archive: {total_archive}"
        )

    except Exception as ex:
        log.error(f"Помилка: {ex}")
        db.rollback()
    finally:
        db.close()

    return stats


if __name__ == "__main__":
    log.info("=== SecMon Maintenance START ===")
    result = run_maintenance()
    log.info(f"=== Готово: {result} ===")
