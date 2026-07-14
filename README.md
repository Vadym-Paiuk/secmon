# SecMon

**Програмне забезпечення організації, оптимізації та вибору зберігання даних в системах та засобах протидії комп'ютерним атакам з урахуванням історичного аспекту їх використання та глибини горизонту**

Централізована система моніторингу мережевої безпеки з ієрархічним зберіганням подій, крос-джерельною кореляцією та централізованим управлінням агентами.

---

## Архітектура

```
Клієнтські вузли (Windows)
├── Windows Firewall → Event Log (канал Security, ID: 5152/5154/5156/5157)
├── Snort 2.9 IDS   → alert_fast лог
└── Python-агент    → нормалізація → HTTP POST батчами

Центральний сервер
├── FastAPI          → REST API
├── PostgreSQL       → ієрархічне зберігання (operational / analytical / archive)
├── Grafana          → візуалізація часових рядів
└── React dashboard  → таблиці подій, алертів, вузлів, шарів
```

---

## Реалізовані методи

### 1. Організація зберігання даних
Трирівнева ієрархія:
- **Operational** — останні 72 години, всі нові події
- **Analytical** — підтверджені інциденти (effectiveness ≥ 0.4), зберігаються до 90 днів
- **Archive** — застарілі події без підтвердженої цінності, зберігаються до 1 року

### 2. Оптимізація даних
- Фільтрація шуму на рівні агента (`min_severity`, `noise_ports`)
- Індекси PostgreSQL по `src_ip`, `ts`, `source`, `layer`
- Батчева відправка подій
- Централізоване керування параметрами агентів через сервер

### 3. Вибір даних з урахуванням горизонту
- Поле `effectiveness` (0.0–1.0) — підвищується при крос-кореляції
- Ретроактивне оновлення: підтверджені події переводяться в `analytical` і не архівуються
- `maintenance.py` щоденно переміщує дані між шарами за часовими горизонтами

---

## Структура проєкту

```
secmon/
├── server/
│   ├── main.py           # FastAPI сервер, кореляція, API
│   ├── models.py         # SQLAlchemy ORM (Node, Event, EventArchive, Alert, Config)
│   ├── schemas.py        # Pydantic схеми
│   ├── database.py       # підключення до PostgreSQL
│   ├── maintenance.py    # щоденне обслуговування шарів зберігання
│   ├── requirements.txt
│   └── .env.example      # шаблон змінних середовища
├── agent/
│   ├── agent.py          # головний агент (3 потоки: збір / flush / heartbeat+config)
│   ├── firewall_reader.py# читання Windows Firewall Event Log
│   ├── snort_reader.py   # tail-читач Snort alert_fast логу
│   ├── simulate_events.py# генератор тестових подій
│   ├── config.yaml       # локальний конфіг агента
│   └── requirements.txt
└── dashboard/            # React додаток
    └── src/
        ├── App.jsx
        └── components/
            ├── StatCard.jsx
            ├── Badge.jsx
            ├── EventsTable.jsx
            ├── AlertsTable.jsx
            ├── NodesPanel.jsx
            └── LayersPanel.jsx
```

---

## Встановлення та розгортання

### Крок 1: Встановити залежності

- [Python 3.13+](https://python.org)
- [Node.js 22+](https://nodejs.org)
- [PostgreSQL 16](https://postgresql.org/download/windows)
- [Snort 2.9-WIN64](https://snort.org/downloads) + [Npcap](https://npcap.com)
- [Grafana OSS](https://grafana.com/grafana/download)

### Крок 2: База даних

В pgAdmin або psql створити БД:

```sql
CREATE DATABASE secmon;
```

### Крок 3: Сервер

```powershell
cd server
pip install -r requirements.txt
copy .env.example .env
```

Відкрити `.env` і вписати свій пароль PostgreSQL:

```
DATABASE_URL=postgresql://postgres:ТВІЙ_ПАРОЛЬ@localhost:5432/secmon
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
```

Запусти сервер — він автоматично створить таблиці:

```powershell
python main.py
```

### Крок 4: Додати колонки в БД

Після першого запуску сервера в pgAdmin (Query Tool):

```sql
ALTER TABLE events ADD COLUMN IF NOT EXISTS effectiveness FLOAT DEFAULT 0.0;
ALTER TABLE events ADD COLUMN IF NOT EXISTS layer VARCHAR DEFAULT 'operational';
ALTER TABLE events ADD COLUMN IF NOT EXISTS correlated_alert_id INTEGER;
ALTER TABLE events ADD COLUMN IF NOT EXISTS protocol VARCHAR;
ALTER TABLE events ADD COLUMN IF NOT EXISTS direction VARCHAR;
ALTER TABLE events ADD COLUMN IF NOT EXISTS threat_class VARCHAR;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlated_ips JSON;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS confidence FLOAT DEFAULT 0.5;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS incident_type VARCHAR;
```

### Крок 5: Індекси в БД

```sql
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_layer ON events(layer);
```

### Крок 6: Увімкнути аудит Windows Firewall (один раз, від адміністратора)

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

### Крок 7: Агент (від імені адміністратора)

```powershell
cd agent
pip install -r requirements.txt
```

Відкрий `config.yaml` і вкажи IP сервера:

```yaml
server_url: "http://192.168.0.X:8000"
```

```powershell
python agent.py
```

### Крок 8: Snort ( від адміністратора)

Дізнатися номер мережевого інтерфейсу:

```powershell
C:\Snort\bin\snort.exe -W
```

Запусти:

```powershell
C:\Snort\bin\snort.exe -i <НОМЕР ІНТЕРФЕЙСУ> -c C:\Snort\etc\snort.conf -l C:\Snort\log -A fast -K ascii
```

### Крок 9: Дашборд

```powershell
cd dashboard
npm install
npm start
```

Відкриється на `http://localhost:3001`.

### Крок 10: Перевірка

```powershell
cd agent
python simulate_events.py
```

Відкрити `http://localhost:8000/api/stats/summary` — має повернути статистику з подіями.

---

## API ендпоінти

| Метод | URL | Опис |
|---|---|---|
| GET | `/api/stats/summary` | Загальна статистика |
| GET | `/api/stats/layers` | Розподіл по шарах зберігання |
| GET | `/api/events` | Список подій (фільтри: source, layer, node_id) |
| GET | `/api/alerts` | Список алертів |
| GET | `/api/nodes` | Список вузлів та їх статус |
| POST | `/api/heartbeat` | Реєстрація вузла (викликає агент) |
| POST | `/api/events` | Прийом батчу подій від агента |
| GET | `/api/configs/{node_id}` | Отримати конфіг для вузла |
| POST | `/api/configs/{node_id}` | Встановити конфіг для вузла |


---

## Централізоване управління агентами

Конфіг агента керується з сервера без перезапуску. Агент перевіряє нову версію при кожному heartbeat (до 30 сек затримки):

```powershell
curl -X POST "http://localhost:8000/api/configs/<НАЗВА ХОСТА (наприклад DESKTOP-45A774)>" ^
  -H "Content-Type: application/json" ^
  -d "{\"min_severity\": 3, \"snort_enabled\": true, \"flush_interval\": 20}"
```

Керовані параметри: `min_severity`, `noise_ports`, `flush_interval`, `heartbeat_interval`, `snort_enabled`, `firewall_event_ids`.

---

## Обслуговування БД

```powershell
cd server
python maintenance.py
```

Рекомендується запускати через Windows Task Scheduler раз на добу.

---

## Увімкнення аудиту Windows Firewall

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

---
