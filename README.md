# Бұлттық қауіпсіздік сканері (AWS Cloud Scanner)

AWS бұлттық инфрақұрылымындағы конфигурациялық осалдықтарды автоматты түрде анықтауға, CIS AWS Foundations Benchmark қауіпсіздік стандарттарына сәйкестікті тексеруге және жалпы қауіпсіздік деңгейін бағалауға арналған консольдік бағдарламалық кешен.

Бұл жоба дипломдық жұмыс аясында әзірленген. Жүйе 15 кешенді тексеру ережесін қамтиды.

---

## 🛠 Технологиялық стек
- **Python**: 3.11+
- **Web Framework**: `FastAPI` + `Uvicorn` (REST API & Web Dashboard)
- **AWS SDK**: `boto3` (бұлттық ресурстармен байланыс)
- **IaC Parser**: `python-hcl2` (Terraform .tf файлдарын статикалық талдау)
- **Шаблонизатор**: `jinja2` (автономды интерактивті HTML-есептер құрастыру)
- **Тестілеу**: `pytest`, `httpx` (33 кешенді тест)
- **Модельдеу / Мок**: `moto` (нақты AWS шығындарынсыз оқшауланған тестілеу)
- **Контейнеризация**: `Docker`, `docker-compose`

---

## 📁 Жоба құрылымы

```text
Diplom/
├── scanner.py              # Негізгі CLI және Web орындау нүктесі (--web, --iac қолдауымен)
├── Dockerfile              # Контейнерлеу конфигурациясы
├── docker-compose.yml      # Жүйені бір командамен On-Premise көтеру
├── api/                    # FastAPI REST API қызметі
│   ├── __init__.py
│   ├── main.py             # FastAPI негізгі кіру нүктесі және CORS
│   ├── routes.py           # /api/v1/scan, /rules, /report эндпоинттері
│   └── schemas.py          # Pydantic деректер сұлбалары
├── web/                    # Заманауи Web UI дашборды
│   └── index.html          # TailwindCSS негізіндегі интерактивті панель
├── iac/                    # IaC (Terraform) Shift-Left сканері
│   ├── __init__.py
│   ├── parser.py           # python-hcl2 негізінде .tf файлдарын оқу
│   ├── rules.py            # Terraform статикалық қауіпсіздік ережелері
│   └── scanner.py          # IaC сканерлеу қозғалтқышы
├── core/                   # Бағдарламаның негізгі компоненттері
│   ├── __init__.py
│   ├── models.py           # Finding, Severity және Remediation үлгілері
│   ├── drift.py            # Бұлт пен код арасындағы Drift анықтау қозғалтқышы
│   ├── engine.py           # Тексерулерді табу және оқшаулап орындау жүйесі
│   ├── registry.py         # @register_check декораторы және тексерулер тізілімі
│   └── scoring.py          # Тұрақты салмақталған қауіпсіздік балын (0-100) есептеу
├── checks/                 # Аудит жүргізу ережелері (15 тексеру)
│   ├── __init__.py
│   ├── ec2.py              # EC2-001, EC2-002, EC2-003, EC2-004 тексерулері
│   ├── s3.py               # S3-001, S3-002, S3-003 тексерулері
│   ├── iam.py              # IAM-001, IAM-002, IAM-003, IAM-004, IAM-005 тексерулері
│   ├── rds.py              # RDS-001 тексеруі
│   └── cloudtrail.py       # CT-001, CT-002 тексерулері
├── report/                 # Есепті генерациялау модульдері
│   ├── __init__.py
│   ├── html_report.py      # Jinja2 негізінде автономды HTML-есеп жасау
│   ├── json_report.py      # Нәтижелерді JSON форматына экспорттау
│   └── template.html       # Интерактивті сүзгісі бар HTML үлгісі (<html lang="kk">)
├── scripts/                # Қосымша утилиталар
│   └── setup_vulnerable_env.py # Эмуляторды осал ресурстармен толтыру/тазалау
├── tests/                  # Автоматтандырылған тесттер (33 тест)
│   ├── test_api.py         # FastAPI эндпоинттерін тестілеу
│   ├── test_drift.py       # Drift Detection қозғалтқышын тестілеу
│   ├── test_iac.py         # Terraform парсерін және ережелерін тестілеу
│   ├── test_scoring.py     # Бағалау формуласының дұрыстығын тексеру
│   ├── test_ec2_checks.py  # moto арқылы EC2 және EBS тексерулерін тестілеу
│   ├── test_other_checks.py# S3, IAM, RDS, CloudTrail тексерулеріне арналған тесттер
│   └── test_report.py      # HTML және JSON жасалуын тестілеу
├── pytest.ini              # pytest конфигурациясы
├── requirements.txt        # Тәуелділіктер тізімі
├── .gitignore              # Git ескермейтін файлдар тізімі
└── README.md               # Құжаттама және нұсқаулық
```

---

## 🚀 Орнату және баптау

Барлық командалар жобаның түбірлік каталогынан (`Diplom`) орындалуы тиіс:

```bash
cd Diplom

# 1. Виртуалды ортаны құру
python -m venv venv

# 2. Виртуалды ортаны белсендіру
# Windows:
venv\Scripts\activate
# Linux / macOS:
# source venv/bin/activate

# 3. Қажетті тәуелділіктерді орнату
pip install -r requirements.txt
```

---

## 🧪 Тесттерді іске қосу

Жобадағы барлық модульдер (AWS ережелері, IaC сканері, Drift қозғалтқышы және REST API) `pytest`, `httpx` және `moto` кітапханалары арқылы толық тестіленген (барлығы 33 кешенді тест):

```bash
cd Diplom
pytest -v
```

---

## 💻 Бағдарламаны іске қосу нұсқаулығы

### 1. Интерактивті Web Dashboard және REST API іске қосу
```bash
# Веб-серверді 8000 портында көтеру:
python scanner.py --web --port 8000

# Браузер арқылы ашу:
# Веб-дашборд:          http://localhost:8000/dashboard
# Swagger құжаттамасы:   http://localhost:8000/docs
```

### 2. Docker арқылы оқшауланған түрде іске қосу (On-Premise)
```bash
# Барлық жүйені контейнерде көтеру:
docker compose up -d --build
```

### 3. CLI арқылы кешенді сканерлеу (AWS + Terraform IaC + Drift)
```bash
# Terraform кодын және AWS бұлтын қатар тексеру:
python scanner.py --iac ./terraform-code/ --output report.html
```

### 4. LocalStack / moto_server арқылы тестілеу
```bash
# Тесттік осал ортаны дайындау:
python scripts/setup_vulnerable_env.py --endpoint-url http://localhost:4566

# Сканерлеуді іске қосу (негізгі аймақ):
python scanner.py --endpoint-url http://localhost:4566 --region us-east-1 --output report.html

# Барлық аймақтар бойынша сканерлеу:
python scanner.py --endpoint-url http://localhost:4566 --all-regions --output report.html

# Тесттік ресурстарды толық тазалау:
python scripts/setup_vulnerable_env.py --endpoint-url http://localhost:4566 --cleanup
```

### 2. Нақты AWS инфрақұрылымында іске қосу (SecurityAudit саясатымен)
```bash
aws configure --profile audit-profile
python scanner.py --profile audit-profile --region us-east-1 --all-regions --output report.html
```

---

## 🛡 Қауіпсіздік тексерулерінің толық тізімі (15 ереже)

| Код | Деңгей | Ресурс | Сипаттамасы | Стандарт |
|---|---|---|---|---|
| **EC2-001** | HIGH | EC2 | SSH (22-порт) бүкіл интернетке (0.0.0.0/0) ашық | CIS AWS Benchmark 5.2 |
| **EC2-002** | MEDIUM | EBS | Шифрланбаған EBS томы | CIS AWS Benchmark 2.2.1 |
| **EC2-003** | HIGH | EC2 | RDP (3389-порт) бүкіл интернетке (0.0.0.0/0) ашық | CIS AWS Benchmark 5.3 |
| **EC2-004** | HIGH | EC2 | Security Group барлық трафикті (-1 немесе 0-65535) ашық қалдырған | CIS AWS Benchmark 5.1 |
| **S3-001** | HIGH | S3 | S3 бакетінде Public Access Block өшірілген | CIS AWS Benchmark 2.1.5 |
| **S3-002** | MEDIUM | S3 | S3 бакетінде әдепкі серверлік шифрлау (SSE) жоқ | CIS AWS Benchmark 2.1.1 |
| **S3-003** | LOW | S3 | S3 бакетінде нұсқалылық (Versioning) қосылмаған | CIS AWS Benchmark 2.1.3 |
| **IAM-001** | MEDIUM | IAM | Консольдік құпиясөзі бар пайдаланушыда MFA жоқ | CIS AWS Benchmark 1.10 |
| **IAM-002** | CRITICAL | IAM | Root аккаунтында MFA құрылғысы қосылмаған | CIS AWS Benchmark 1.5 |
| **IAM-003** | MEDIUM | IAM | 90 күннен ескірген белсенді IAM Access Key | CIS AWS Benchmark 1.14 |
| **IAM-004** | CRITICAL | IAM | Саясатта толық әкімшілік рұқсат (Action '*' және Resource '*') | CIS AWS Benchmark 1.16 |
| **IAM-005** | LOW | IAM | Құпиясөз саясаты (Password Policy) әлсіз немесе жоқ | CIS AWS Benchmark 1.8 |
| **RDS-001** | CRITICAL | RDS | Деректер қоры интернетке жария қолжетімді (PubliclyAccessible) | CIS AWS Benchmark 2.3.1 |
| **CT-001** | HIGH | CloudTrail | Есептік жазбада белсенді CloudTrail трейлі жоқ | CIS AWS Benchmark 3.1 |
| **CT-002** | LOW | CloudTrail | CloudTrail лог-файлдарының тұтастығын тексеру өшірулі | CIS AWS Benchmark 3.2 |

---

## 📊 Салмақталған бағалау формуласы (Weighted Compliance & Diminishing Penalty)

Бұрынғы қарапайым шегеру формуласы көптеген ресурстар болғанда бағаны лезде 0-ге түсіретін. Жаңа тұрақты формула екі маңызды принципке негізделген:
1. **Шекті кему заңы (Diminishing Return)**: Бір ереже бойынша бірнеше ресурс бұзылса, бірінші ресурс 100% салмақ алады, ал келесілері шекті салмақ (+25%, максимум екі есеге дейін) қосады.
2. **Қамтуға қатысты нормалау**: Штраф жалпы тексерулер санына қатысты есептеледі:
   $$\text{Penalty}_r = W(\text{severity}) \times \left(1 + 0.25 \times \min(n_r - 1, 4)\right)$$
   $$\text{Score} = \max\left(0, 100 - \text{round}\left(\frac{\sum \text{Penalty}_r}{\text{total\_checks} \times 7} \times 100\right)\right)$$
