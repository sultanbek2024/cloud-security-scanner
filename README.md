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
- **Тестілеу**: `pytest`, `httpx` (49 кешенді тест)
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
├── tests/                  # Автоматтандырылған тесттер (49 тест)
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

Жобадағы барлық модульдер (AWS ережелері, IaC сканері, Drift қозғалтқышы және REST API) `pytest`, `httpx` және `moto` кітапханалары арқылы толық тестіленген (барлығы 49 кешенді тест):

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

### 5. Нақты AWS инфрақұрылымында іске қосу (Ең аз рұқсат қағидасы - Least Privilege)
Сканер AWS API метадеректерін тек **read-only** режимінде оқиды. AWS-те сканерлеу үшін арнайы басқарылатын `SecurityAudit` саясатын немесе жобадағы ең төменгі рұқсаттар берілген жеке саясатты қолдануға болады:
- Толық минималды JSON саясаты: [`docs/minimal_iam_policy.json`](docs/minimal_iam_policy.json)

```bash
aws configure --profile audit-profile
python scanner.py --profile audit-profile --region us-east-1 --all-regions --output report.html
```

### 6. Автоматты түзету скрипті (Remediation Engine)
Стендті қауіпсіздендіру немесе өндірістік ортаға дайындық:
```bash
# Өзгеріс енгізбей, жоспарланған әрекеттерді тексеру (Dry-Run):
python scripts/remediate_env.py --dry-run

# Сенімді ішкі желіні (VPN/корпоративтік CIDR) көрсете отырып түзету:
python scripts/remediate_env.py --trusted-cidr 10.0.0.0/8 --yes
```

---

## 🛡 Қауіпсіздік тексерулерінің толық тізімі (15 ереже)

| Код | Деңгей | Ресурс | Сипаттамасы | Стандарт |
|---|---|---|---|---|
| **EC2-001** | HIGH | EC2 | SSH (22-порт) бүкіл интернетке (0.0.0.0/0) ашық | CIS 5.2 / FSBP EC2.13 |
| **EC2-002** | MEDIUM | EBS | Шифрланбаған EBS томы | CIS 2.2.1 / FSBP EC2.3 |
| **EC2-003** | HIGH | EC2 | RDP (3389-порт) бүкіл интернетке (0.0.0.0/0) ашық | CIS 5.3 / FSBP EC2.14 |
| **EC2-004** | HIGH | EC2 | Security Group барлық трафикті (-1 немесе 0-65535) ашық қалдырған | CIS 5.4 / FSBP EC2.19 |
| **S3-001** | HIGH | S3 | S3 бакетінде Public Access Block өшірілген | CIS 2.1.4 (v3) / 2.1.5 (v1.4) |
| **S3-002** | MEDIUM | S3 | S3 бакетінде әдепкі серверлік шифрлау (SSE) жоқ | CIS 2.1.1 / FSBP S3.4 |
| **S3-003** | LOW | S3 | S3 бакетінде нұсқалылық (Versioning) қосылмаған | CIS 2.1.3 (Алғышарт) / FSBP S3.14 |
| **IAM-001** | MEDIUM | IAM | Консольдік құпиясөзі бар пайдаланушыда MFA жоқ | CIS 1.5 / FSBP IAM.5 |
| **IAM-002** | CRITICAL | IAM | Root аккаунтында MFA құрылғысы қосылмаған | CIS 1.6 / FSBP IAM.4 |
| **IAM-003** | MEDIUM | IAM | 90 күннен ескірген белсенді IAM Access Key | CIS 1.13 (v3) / 1.14 (v1.4) |
| **IAM-004** | CRITICAL | IAM | Саясатта толық әкімшілік рұқсат (Action '*' және Resource '*') | CIS 1.16 / FSBP IAM.1 |
| **IAM-005** | LOW | IAM | Құпиясөз саясаты (Password Policy) әлсіз немесе жоқ | CIS 1.8 / FSBP IAM.7 |
| **RDS-001** | CRITICAL | RDS | Деректер қоры интернетке жария қолжетімді (PubliclyAccessible) | CIS 2.3.2 (v3) / FSBP RDS.2 |
| **CT-001** | HIGH | CloudTrail | Есептік жазбада белсенді CloudTrail трейлі жоқ | CIS 3.1 / FSBP CloudTrail.1 |
| **CT-002** | LOW | CloudTrail | CloudTrail лог-файлдарының тұтастығын тексеру өшірулі | CIS 3.2 / FSBP CloudTrail.2 |

---

## 📊 Салмақталған бағалау формуласы (Piecewise-Linear Diminishing Penalty Model)

Бұрынғы қарапайым сызықтық қосынды моделі көптеген біртекті ресурстар болғанда (мысалы, бірнеше қауіпсіздік тобындағы ашық SSH) бағаны лезде 0-ге түсіретін. Жаңа математикалық модель екі маңызды принципке негізделген:
1. **Қанығуы бар кемімелі айыппұл заңы (Diminishing Return / Saturation)**: Бір ереже бойынша бірнеше ресурс бұзылса, бірінші ресурс 100% салмақ алады ($W_r$), ал әрбір келесі ресурс +25% қосады (максимум екі еселік базалық салмаққа дейін, $n \ge 5$ кезінде).
2. **Толық сыйымдылыққа қатысты нормалау ($C = 168$)**: Штраф шкаласының максималды сыйымдылығы 15 ереженің барлығы бірнеше рет бұзылған кездегі абсолютті шегіне ($C = \sum 2 \times W_r = 168$) қатысты нормаланады:
   $$\text{Penalty}_r = W(\text{severity}) \times \left(1 + 0.25 \times \min(n_r - 1, 4)\right)$$
   $$\text{Normalized Penalty} = \min\left(100.0, \frac{\sum \text{Penalty}_r}{C} \times 100.0\right)$$
   $$\text{Score} = \max\left(0, 100 - \text{round}(\text{Normalized Penalty})\right)$$
3. **Сыни қауіптерді шектеу шарты (Critical Rule Cap)**: Егер инфрақұрылымда тым болмаса бір шешілмеген CRITICAL деңгейлі осалдық қалса, жүйенің есептелген сандық ұпайы жоғары болса да (мысалы, 94/100), әріптік рейтинг **«B (Жақсы)»** деңгейінен аспайды («A» бұғатталады). Бұл корпоративтік қауіпсіздік талаптарына толық сәйкес келеді.
