import os
import sys
import pptx
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def build_satbayev_light_deck():
    prs = pptx.Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SATBAYEV UNIVERSITY OFFICIAL LIGHT PALETTE
    # (Based on sso.satbayev.university & CloudSec Light UI)
    # =========================================================================
    BG_PAGE = RGBColor(241, 245, 249)        # #F1F5F9 Soft light gray-blue
    SATBAYEV_BLUE = RGBColor(0, 86, 179)     # #0056B3 Satbayev Royal Blue
    SATBAYEV_CYAN = RGBColor(0, 163, 224)    # #00A3E0 Satbayev Cyan
    HEADER_BLUE = RGBColor(0, 98, 189)       # #0062BD Portal Header Blue
    
    CARD_BG = RGBColor(255, 255, 255)        # Pure White
    CARD_BORDER = RGBColor(219, 228, 238)    # #DBE4EE Soft Slate Border
    CARD_BORDER_BLUE = RGBColor(186, 214, 245) # #BAD6F5 Accent Border
    
    TEXT_DARK = RGBColor(15, 23, 42)         # #0F172A Dark Slate
    TEXT_MUTED = RGBColor(71, 85, 105)       # #475569 Slate Muted
    TEXT_LIGHT_MUTED = RGBColor(100, 116, 139) # #64748B Secondary
    WHITE = RGBColor(255, 255, 255)
    
    ACCENT_AMBER = RGBColor(217, 119, 6)     # #D97706 Warning/Critical
    ACCENT_EMERALD = RGBColor(16, 185, 129)  # #10B981 Pass/Safe
    ACCENT_RED = RGBColor(220, 38, 38)       # #DC2626 Critical Red
    
    FONT_NAME = "Arial"

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_PAGE
        bg.line.fill.background()
        return bg

    def add_satbayev_header(slide, title, category="SATBAYEV UNIVERSITY • АҚПАРАТТЫҚ ҚАУІПСІЗДІК", slide_num=1):
        set_slide_background(slide)
        
        # Solid Top Blue Header Bar (Like SSO & CloudSec portal)
        hdr = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(1.15))
        hdr.fill.solid()
        hdr.fill.fore_color.rgb = SATBAYEV_BLUE
        hdr.line.fill.background()
        
        # Accent Cyan Strip below header
        strip = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, Inches(1.15), prs.slide_width, Inches(0.04))
        strip.fill.solid()
        strip.fill.fore_color.rgb = SATBAYEV_CYAN
        strip.line.fill.background()

        # Category / Breadcrumb
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.18), Inches(9.0), Inches(0.28))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        tf_cat.margin_left = tf_cat.margin_right = tf_cat.margin_top = tf_cat.margin_bottom = 0
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category.upper()
        p_cat.font.size = Pt(9.5)
        p_cat.font.bold = True
        p_cat.font.color.rgb = RGBColor(186, 230, 253) # Light cyan text
        p_cat.font.name = FONT_NAME

        # Title
        t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.48), Inches(9.8), Inches(0.55))
        tf_t = t_box.text_frame
        tf_t.word_wrap = True
        tf_t.margin_left = tf_t.margin_right = tf_t.margin_top = tf_t.margin_bottom = 0
        p_t = tf_t.paragraphs[0]
        p_t.text = title
        p_t.font.size = Pt(19)
        p_t.font.bold = True
        p_t.font.color.rgb = WHITE
        p_t.font.name = FONT_NAME

        # Slide Number Pill Badge (Top Right)
        badge = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(11.4), Inches(0.35), Inches(1.15), Inches(0.42))
        badge.fill.solid()
        badge.fill.fore_color.rgb = RGBColor(255, 255, 255)
        badge.line.color.rgb = RGBColor(255, 255, 255)
        badge.line.width = Pt(1)
        tf_badge = badge.text_frame
        tf_badge.vertical_anchor = MSO_ANCHOR.MIDDLE
        p_b = tf_badge.paragraphs[0]
        p_b.alignment = PP_ALIGN.CENTER
        p_b.text = f"{slide_num:02d} / 12"
        p_b.font.size = Pt(11)
        p_b.font.bold = True
        p_b.font.color.rgb = SATBAYEV_BLUE
        p_b.font.name = FONT_NAME

    def add_white_card(slide, left, top, width, height, border=CARD_BORDER):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_BG
        card.line.color.rgb = border
        card.line.width = Pt(1.2)
        return card

    # =========================================================================
    # SLIDE 1: ТИТУЛДЫҚ БЕТ (TITLE SLIDE) - LIGHT THEME
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # University Top Header Bar (Solid Satbayev Blue)
    hdr1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(1.3))
    hdr1.fill.solid()
    hdr1.fill.fore_color.rgb = SATBAYEV_BLUE
    hdr1.line.fill.background()

    strip1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, Inches(1.3), prs.slide_width, Inches(0.05))
    strip1.fill.solid()
    strip1.fill.fore_color.rgb = SATBAYEV_CYAN
    strip1.line.fill.background()

    univ_box = s1.shapes.add_textbox(Inches(0.8), Inches(0.2), Inches(11.733), Inches(0.95))
    tf1 = univ_box.text_frame
    tf1.word_wrap = True
    p1 = tf1.paragraphs[0]
    p1.alignment = PP_ALIGN.CENTER
    p1.text = "ҚАЗАҚСТАН РЕСПУБЛИКАСЫ ҒЫЛЫМ ЖӘНЕ ЖОҒАРЫ БІЛІМ МИНИСТРЛІГІ\n«Қ.И. СӘТБАЕВ АТЫНДАҒЫ ҚАЗАҚ ҰЛТТЫҚ ТЕХНИКАЛЫҚ ЗЕРТТЕУ УНИВЕРСИТЕТІ» КЕАҚ"
    p1.font.size = Pt(13)
    p1.font.bold = True
    p1.font.color.rgb = WHITE
    p1.font.name = FONT_NAME

    p1_sub = tf1.add_paragraph()
    p1_sub.alignment = PP_ALIGN.CENTER
    p1_sub.text = "Автоматтандыру және ақпараттық технологиялар институты | Киберқауіпсіздік кафедрасы"
    p1_sub.font.size = Pt(11)
    p1_sub.font.color.rgb = RGBColor(186, 230, 253)
    p1_sub.font.name = FONT_NAME

    # Main Project Title Card
    title_card = add_white_card(s1, Inches(0.8), Inches(1.65), Inches(11.733), Inches(2.5), border=CARD_BORDER_BLUE)
    t_box = s1.shapes.add_textbox(Inches(1.1), Inches(1.85), Inches(11.133), Inches(2.1))
    tf_t = t_box.text_frame
    tf_t.word_wrap = True
    
    p_spec = tf_t.paragraphs[0]
    p_spec.alignment = PP_ALIGN.CENTER
    p_spec.text = "ДИПЛОМДЫҚ ЖОБА"
    p_spec.font.size = Pt(12)
    p_spec.font.bold = True
    p_spec.font.color.rgb = ACCENT_AMBER
    p_spec.font.name = FONT_NAME

    p_topic = tf_t.add_paragraph()
    p_topic.alignment = PP_ALIGN.CENTER
    p_topic.text = "«Бұлттық инфрақұрылымның конфигурациялық осалдықтарын анықтау\nжәне қауіпсіздігін бағалау жүйесін әзірлеу»"
    p_topic.font.size = Pt(22)
    p_topic.font.bold = True
    p_topic.font.color.rgb = SATBAYEV_BLUE
    p_topic.font.name = FONT_NAME

    p_code = tf_t.add_paragraph()
    p_code.alignment = PP_ALIGN.CENTER
    p_code.text = "Мамандығы: 6B06301 – «Ақпараттық қауіпсіздік»"
    p_code.font.size = Pt(12)
    p_code.font.bold = True
    p_code.font.color.rgb = TEXT_MUTED
    p_code.font.name = FONT_NAME

    # Team Card (Left)
    card_team = add_white_card(s1, Inches(0.8), Inches(4.35), Inches(5.7), Inches(2.2))
    tb_team = s1.shapes.add_textbox(Inches(1.1), Inches(4.5), Inches(5.1), Inches(1.9))
    tf_team = tb_team.text_frame
    tf_team.word_wrap = True
    p_th = tf_team.paragraphs[0]
    p_th.text = "ОРЫНДАҒАНДАР:"
    p_th.font.size = Pt(11)
    p_th.font.bold = True
    p_th.font.color.rgb = SATBAYEV_BLUE
    p_th.font.name = FONT_NAME

    team_members = [
        "• Гапуов Алишер Бегзатұлы",
        "• Адразах Султанбек Шахзатұлы",
        "• Джумагельдиев Ернұр Бақытұлы"
    ]
    for mem in team_members:
        pm = tf_team.add_paragraph()
        pm.text = mem
        pm.font.size = Pt(12)
        pm.font.bold = True
        pm.font.color.rgb = TEXT_DARK
        pm.font.name = FONT_NAME
        pm.space_before = Pt(4)

    # Supervisor Card (Right)
    card_sup = add_white_card(s1, Inches(6.833), Inches(4.35), Inches(5.7), Inches(2.2))
    tb_sup = s1.shapes.add_textbox(Inches(7.1), Inches(4.5), Inches(5.1), Inches(1.9))
    tf_sup = tb_sup.text_frame
    tf_sup.word_wrap = True
    p_sh = tf_sup.paragraphs[0]
    p_sh.text = "ЖЕТЕКШІЛЕР:"
    p_sh.font.size = Pt(11)
    p_sh.font.bold = True
    p_sh.font.color.rgb = SATBAYEV_BLUE
    p_sh.font.name = FONT_NAME

    sups = [
        "Ғылыми жетекші: Каламан Е.Т., аға оқытушы",
        "Рецензент: Оразбеков Ж.Н., т.ғ.к., қауым. профессор",
        "КҚ кафедрасының меңгерушісі: Ягалиева Б.Е., ф.-м.ғ.к."
    ]
    for sp in sups:
        ps = tf_sup.add_paragraph()
        ps.text = sp
        ps.font.size = Pt(11.5)
        ps.font.color.rgb = TEXT_DARK
        ps.font.name = FONT_NAME
        ps.space_before = Pt(4)

    # Footer Date
    f_box = s1.shapes.add_textbox(Inches(0.8), Inches(6.8), Inches(11.733), Inches(0.4))
    tf_f = f_box.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.alignment = PP_ALIGN.CENTER
    p_f.text = "Алматы, 2026 ж."
    p_f.font.size = Pt(11)
    p_f.font.bold = True
    p_f.font.color.rgb = TEXT_LIGHT_MUTED
    p_f.font.name = FONT_NAME

    # =========================================================================
    # SLIDE 2: ЗЕРТТЕУДІҢ ӨЗЕКТІЛІГІ ЖӘНЕ МӘСЕЛЕНІҢ ҚОЙЫЛУЫ
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s2, "Зерттеудің өзектілігі және мәселенің қойылуы", "ӨЗЕКТІЛІК ЖӘНЕ ҚАУІПТЕР", 2)

    cards_data = [
        ("CSA Top Threats (2026)", ACCENT_AMBER, [
            "Cloud Security Alliance ұйымының 2026 жылғы зерттеуінде сәйкестендіру мен қолжетімділікті (IAM) дұрыс басқармау қауіптердің 1-орнында.",
            "Бұлттық ресурстар API және автоматты құралдармен өте жылдам құрылып, өзгертіледі.",
            "Қате бапталған бір саясат жүздеген қызметке бір мезгілде қауіп төндіреді."
        ]),
        ("Shared Responsibility Model", SATBAYEV_BLUE, [
            "AWS ортақ жауапкершілік моделі: Провайдер инфрақұрылымның өзін (Hardware/Hypervisor) қорғайды.",
            "Қызметтердің конфигурациясы, саясаттары және деректердің қорғалуы тапсырыс берушінің міндетінде қалады.",
            "Қолмен жүргізілетін аудит бұлттың жылдам өзгеруіне ілесе алмайды."
        ]),
        ("ClickOps vs IaC қақтығысы", ACCENT_RED, [
            "Инфрақұрылым код (Terraform) түрінде сипатталса да, әкімшілер консольде қолмен өзгеріс енгізеді.",
            "Бұл жағдай Configuration Drift және Shadow Infrastructure тәуекелдерін тудырады.",
            "Қысқа мерзімді қауіпті өзгерістер мерзімді сканерлеу кезінде көрінбей қалады."
        ])
    ]

    for i, (head, col, bullets) in enumerate(cards_data):
        x = Inches(0.8 + i * 4.0)
        card = add_white_card(s2, x, Inches(1.45), Inches(3.7), Inches(5.6))
        
        top_bar = s2.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, Inches(1.45), Inches(3.7), Inches(0.08))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = col
        top_bar.line.fill.background()

        tb = s2.shapes.add_textbox(x + Inches(0.2), Inches(1.65), Inches(3.3), Inches(5.2))
        tf = tb.text_frame
        tf.word_wrap = True
        
        ph = tf.paragraphs[0]
        ph.text = head
        ph.font.size = Pt(14)
        ph.font.bold = True
        ph.font.color.rgb = col
        ph.font.name = FONT_NAME

        for b in bullets:
            pb = tf.add_paragraph()
            pb.text = "• " + b
            pb.font.size = Pt(11.5)
            pb.font.color.rgb = TEXT_DARK
            pb.font.name = FONT_NAME
            pb.space_before = Pt(8)

    # =========================================================================
    # SLIDE 3: ЖҰМЫСТЫҢ МАҚСАТЫ МЕН МІНДЕТТЕРІ
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s3, "Жұмыстың мақсаты мен негізгі міндеттері", "МАҚСАТ ЖӘНЕ МІНДЕТТЕР", 3)

    g_card = add_white_card(s3, Inches(0.8), Inches(1.45), Inches(11.733), Inches(1.45), border=SATBAYEV_BLUE)
    g_tb = s3.shapes.add_textbox(Inches(1.1), Inches(1.6), Inches(11.133), Inches(1.15))
    g_tf = g_tb.text_frame
    g_tf.word_wrap = True
    gp = g_tf.paragraphs[0]
    gp.text = "ЖҰМЫСТЫҢ БАСТЫ МАҚСАТЫ:"
    gp.font.size = Pt(11)
    gp.font.bold = True
    gp.font.color.rgb = SATBAYEV_BLUE
    gp.font.name = FONT_NAME
    
    gp2 = g_tf.add_paragraph()
    gp2.text = "AWS бұлттық инфрақұрылымы мен Terraform кодтарындағы конфигурациялық осалдықтарды автоматты анықтайтын, ауытқуларды (Drift) талдайтын және қауіпсіздік деңгейін ғылыми негізде бағалайтын жүйе әзірлеу."
    gp2.font.size = Pt(14)
    gp2.font.bold = True
    gp2.font.color.rgb = TEXT_DARK
    gp2.font.name = FONT_NAME
    gp2.space_before = Pt(4)

    tasks = [
        ("1. Әдістемелік және нормативтік талдау", "NIST CSF 2.0, CIS Benchmarks стандарттарын зерттеу, қолданыстағы CSPM және IaC шешімдерінің шектеулерін анықтау."),
        ("2. 15 Базалық қауіпсіздік тексеру ережесін құру", "EC2, EBS, S3, IAM, RDS және CloudTrail қызметтері үшін boto3 негізінде автоматтандырылған аудит модулін іске асыру."),
        ("3. Configuration Drift детекторын әзірлеу", "Бұлттағы нақты күй (Live AWS) мен Terraform сипаттамасын салыстырып, рұқсатсыз өзгерістер мен Shadow IT-ді табу."),
        ("4. Скоринг және уақыттық модельді құру", "Әділ салмақтық 0-100 бағалау шкаласын жасау және сенім қатынастарын талдайтын TrustGap-CSPM моделін негіздеу.")
    ]

    for i, (th, td) in enumerate(tasks):
        col_idx = i % 2
        row_idx = i // 2
        cx = Inches(0.8 + col_idx * 5.95)
        cy = Inches(3.1 + row_idx * 1.95)
        
        c = add_white_card(s3, cx, cy, Inches(5.78), Inches(1.75))
        
        l_bar = s3.shapes.add_shape(MSO_SHAPE.RECTANGLE, cx, cy, Inches(0.08), Inches(1.75))
        l_bar.fill.solid()
        l_bar.fill.fore_color.rgb = SATBAYEV_BLUE
        l_bar.line.fill.background()

        tb = s3.shapes.add_textbox(cx + Inches(0.25), cy + Inches(0.18), Inches(5.35), Inches(1.4))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = th
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = SATBAYEV_BLUE
        p.font.name = FONT_NAME

        p2 = tf.add_paragraph()
        p2.text = td
        p2.font.size = Pt(11)
        p2.font.color.rgb = TEXT_DARK
        p2.font.name = FONT_NAME
        p2.space_before = Pt(4)

    # =========================================================================
    # SLIDE 4: НОРМАТИВТІК ЖӘНЕ ӘДІСТЕМЕЛІК НЕГІЗДЕР
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s4, "Нормативтік және әдістемелік негіздер", "СТАНДАРТТАР ЖӘНЕ САЯСАТТАР", 4)

    standards = [
        ("NIST CSF 2.0 Базасы", SATBAYEV_BLUE, [
            "Govern: Қауіпсіздік стратегиясы мен бақылау саясатын басқару",
            "Identify: Бұлттық активтер мен қатерлерді түгендеу",
            "Protect: Қолжетімділікті және деректер қоймасын қорғау",
            "Detect: Конфигурациялық қателер мен ауытқуларды табу",
            "Respond & Recover: Инциденттерге әрекет ету және қалпына келтіру",
            "NIST SP 800-30: Тәуекелдерді сапалық/сандық матрицалық талдау"
        ]),
        ("CIS AWS Foundations Benchmark", SATBAYEV_CYAN, [
            "Center for Internet Security ресми базалық стандарттары",
            "CIS 1.x: Identity & Access Management (MFA, кілттер мерзімі)",
            "CIS 2.x: Amazon S3 объектілік қоймаларын қорғау талаптары",
            "CIS 3.x: Журналдау және аудит параметрлері (CloudTrail)",
            "CIS 5.x: Желілік қауіпсіздік баптаулары (EC2 Security Groups)",
            "Стандарттарға автоматты сәйкестік мониторингін қамтамасыз ету"
        ]),
        ("AWS IAM Саясаттар Логикасы", ACCENT_AMBER, [
            "Explicit Deny басымдығы (кез келген Allow рұқсатын бұғаттайды)",
            "Permissions Boundary: Сессияның максималды өкілеттік шекарасы",
            "Session Policy: STS уақытша сессияларының шектеулері",
            "Least Privilege: Пайдаланушыларға ең аз қажетті рұқсат беру",
            "Trust Policy: Сыртқы жүйелердің (GitHub Actions т.б.) рөл қабылдауы",
            "Wildcard (*) артық рұқсаттарының қауіптілігін дер кезінде жою"
        ])
    ]

    for i, (title, color, items) in enumerate(standards):
        x = Inches(0.8 + i * 4.0)
        card = add_white_card(s4, x, Inches(1.45), Inches(3.7), Inches(5.6))
        
        top_bar = s4.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, Inches(1.45), Inches(3.7), Inches(0.08))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = color
        top_bar.line.fill.background()

        tb = s4.shapes.add_textbox(x + Inches(0.2), Inches(1.65), Inches(3.3), Inches(5.2))
        tf = tb.text_frame
        tf.word_wrap = True
        
        ph = tf.paragraphs[0]
        ph.text = title
        ph.font.size = Pt(14)
        ph.font.bold = True
        ph.font.color.rgb = color
        ph.font.name = FONT_NAME

        for item in items:
            p = tf.add_paragraph()
            p.text = "• " + item
            p.font.size = Pt(11)
            p.font.color.rgb = TEXT_DARK
            p.font.name = FONT_NAME
            p.space_before = Pt(6)

    # =========================================================================
    # SLIDE 5: ҚОЛДАНЫСТАҒЫ ШЕШІМДЕРДІ САЛЫСТЫРМАЛЫ ТАЛДАУ
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s5, "Қолданыстағы шешімдерді салыстырмалы талдау", "АНАЛОГТАР ЖӘНЕ САЛЫСТЫРУ", 5)

    # Left Card: Comparison Table
    t_card = add_white_card(s5, Inches(0.8), Inches(1.45), Inches(7.0), Inches(5.6))
    t_tb = s5.shapes.add_textbox(Inches(1.0), Inches(1.6), Inches(6.6), Inches(5.3))
    t_tf = t_tb.text_frame
    t_tf.word_wrap = True

    comp_items = [
        ("Prowler (CSPM платформасы):", "Live AWS ортасын терең тексереді, бірақ IaC (Terraform) бастапқы кодымен байланыспайды. ClickOps ауытқуларын (Drift) анықтамайды."),
        ("Checkov & Trivy (IaC статикалық құралдары):", "Terraform кодын орналастыруға дейін өте жақсы тексереді. Бірақ жұмыс істеп тұрған бұлтты қадағаламайды, нақты ортадағы өзгерістерді көрмейді."),
        ("AWS Config & CloudTrail қызметтері:", "Конфигурация тарихы мен API логтарын тіркейді. Дегенмен қысқа мерзімді өзгерістердің барлық аралық күйлерін сақтамауы мүмкін және бірыңғай тәуекел бағасын бермейді."),
        ("CloudSec Auditor (Біздің әзірлеме):", "Live AWS пен Terraform кодын бір мезгілде тексереді, ClickOps Drift-ті табады, 1-Click Remediation ұсынады және 168 сыйымдылықты әділ сандық бағалау жүргізеді.")
    ]

    for h, d in comp_items:
        ph = t_tf.paragraphs[0] if not t_tf.paragraphs[0].text else t_tf.add_paragraph()
        ph.text = h
        ph.font.size = Pt(12.5)
        ph.font.bold = True
        ph.font.color.rgb = SATBAYEV_BLUE if "Біздің" in h else ACCENT_AMBER
        ph.font.name = FONT_NAME
        if t_tf.paragraphs[0] != ph:
            ph.space_before = Pt(8)

        pd = t_tf.add_paragraph()
        pd.text = d
        pd.font.size = Pt(11)
        pd.font.color.rgb = TEXT_DARK
        pd.font.name = FONT_NAME
        pd.space_before = Pt(2)

    # Right Card: Clean Image container with proper padding & breathing room
    r_card = add_white_card(s5, Inches(8.0), Inches(1.45), Inches(4.533), Inches(5.6))
    
    img_prowler = os.path.join("d:\\Diplom", "01_prowler_dashboard.png")
    if os.path.exists(img_prowler):
        s5.shapes.add_picture(img_prowler, Inches(8.2), Inches(1.65), width=Inches(4.133))
    
    tb_ic = s5.shapes.add_textbox(Inches(8.2), Inches(4.2), Inches(4.133), Inches(2.7))
    tf_ic = tb_ic.text_frame
    tf_ic.word_wrap = True
    
    pic_head = tf_ic.paragraphs[0]
    pic_head.text = "Басты ғылыми-тәжірибелік шектеу:"
    pic_head.font.size = Pt(11.5)
    pic_head.font.bold = True
    pic_head.font.color.rgb = ACCENT_RED
    pic_head.font.name = FONT_NAME

    pic_text = tf_ic.add_paragraph()
    pic_text.text = "Snapshot сканерлеу тәсілі ресурстардың өткен шақтағы қысқа мерзімді осалдықтары мен сенім саясаты өзгергеннен кейінгі қалдық рұқсаттарды көрсете алмайды. Бұл TrustGap-CSPM уақыттық моделін құруға негіз болды."
    pic_text.font.size = Pt(10.5)
    pic_text.font.color.rgb = TEXT_DARK
    pic_text.font.name = FONT_NAME
    pic_text.space_before = Pt(4)

    # =========================================================================
    # SLIDE 6: ЖҮЙЕНІҢ АРХИТЕКТУРАСЫ
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s6, "CloudSec Auditor жүйесінің архитектурасы", "АРХИТЕКТУРА ЖӘНЕ ТЕХНОЛОГИЯЛАР", 6)

    layers = [
        ("1. Кіріс интерфейстері (UI / CLI)", SATBAYEV_BLUE, [
            "CLI режимі (scanner.py): Консольдік жылдам сканерлеу",
            "Web Dashboard: FastAPI + Tailwind CSS интуитивті интерфейсі",
            "REST API: /api/v1/scan, /api/v1/rules, /api/v1/report/html",
            "Docker & Compose: Контейнерленген жергілікті орта"
        ]),
        ("2. Талдау қозғалтқыштары (Core Engines)", SATBAYEV_CYAN, [
            "ScanEngine: boto3 сессиясы арқылы 15 ережені орындау",
            "Auto-discovery: checks/ пакетінен модульдерді автоматты табу",
            "iac/parser.py: python-hcl2 арқылы Terraform файлын өңдеу",
            "core/drift.py: Live AWS пен IaC сәйкестендіру"
        ]),
        ("3. Бағалау және есеп беру (Scoring & Reports)", ACCENT_EMERALD, [
            "core/scoring.py: 0-100 сандық балл және A/B/C/D/F рейтингі",
            "Diminishing Penalty: Бір қатенің шексіз айыппұл беруіне жол бермеу",
            "Findings & Drift белгісі: Әрбір қауіпті бірегей нысанға байлау",
            "Экспорт: report.json және интерактивті HTML есебі"
        ])
    ]

    for i, (title, color, items) in enumerate(layers):
        x = Inches(0.8 + i * 4.0)
        card = add_white_card(s6, x, Inches(1.45), Inches(3.7), Inches(5.6))
        
        top_bar = s6.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, Inches(1.45), Inches(3.7), Inches(0.08))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = color
        top_bar.line.fill.background()

        tb = s6.shapes.add_textbox(x + Inches(0.2), Inches(1.65), Inches(3.3), Inches(5.2))
        tf = tb.text_frame
        tf.word_wrap = True
        
        ph = tf.paragraphs[0]
        ph.text = title
        ph.font.size = Pt(14)
        ph.font.bold = True
        ph.font.color.rgb = color
        ph.font.name = FONT_NAME

        for item in items:
            p = tf.add_paragraph()
            p.text = "• " + item
            p.font.size = Pt(11)
            p.font.color.rgb = TEXT_DARK
            p.font.name = FONT_NAME
            p.space_before = Pt(8)

    # =========================================================================
    # SLIDE 7: 15 БАЗАЛЫҚ ҚАУІПСІЗДІК ТЕКСЕРУ ЕРЕЖЕЛЕРІ
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s7, "Іске асырылған 15 қауіпсіздік тексеруі", "ТЕКСЕРУ ЕРЕЖЕЛЕРІ (CHECKS)", 7)

    checks_catalog = [
        ("EC2 & EBS Сервистері (4 ереже)", SATBAYEV_BLUE, [
            "EC2-001 (HIGH): SSH (22-порт) 0.0.0.0/0 үшін ашық",
            "EC2-002 (MED): EBS сақтау томы шифрланбаған",
            "EC2-003 (HIGH): RDP (3389-порт) бүкіл интернетке ашық",
            "EC2-004 (HIGH): Барлық порттарға шектеусіз рұқсат (0-65535)"
        ]),
        ("Amazon S3 Қоймалары (3 ереже)", ACCENT_EMERALD, [
            "S3-001 (HIGH): Block Public Access параметрлері өшірулі",
            "S3-002 (MED): Әдепкі серверлік шифрлау (SSE) орнатылмаған",
            "S3-003 (LOW): Бакеттің нұсқалануы (Versioning) қосылмаған"
        ]),
        ("IAM Сәйкестендіру жүйесі (5 ереже)", ACCENT_AMBER, [
            "IAM-001 (MED): Консоль қолданушыларында MFA жоқ",
            "IAM-002 (CRITICAL): Түбірлік (Root) аккаунтта MFA өшірулі!",
            "IAM-003 (MED): Қолжетімділік кілттерінің жасы > 90 күн",
            "IAM-004 (CRITICAL): Саясатта * артық әкімшілік рұқсаттар бар",
            "IAM-005 (LOW): Тіркелгі құпиясөз саясаты әлсіз"
        ]),
        ("RDS және CloudTrail (3 ереже)", ACCENT_RED, [
            "RDS-001 (CRITICAL): Дерекқор данасы интернетке жария қолжетімді",
            "CT-001 (HIGH): Белсенді көп аймақтық трейл табылмады",
            "CT-002 (LOW): Лог файлдарының тұтастығын тексеру өшірулі"
        ])
    ]

    for i, (title, color, items) in enumerate(checks_catalog):
        col_idx = i % 2
        row_idx = i // 2
        cx = Inches(0.8 + col_idx * 5.95)
        cy = Inches(1.45 + row_idx * 2.8)
        
        c = add_white_card(s7, cx, cy, Inches(5.78), Inches(2.6))
        
        top_bar = s7.shapes.add_shape(MSO_SHAPE.RECTANGLE, cx, cy, Inches(5.78), Inches(0.06))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = color
        top_bar.line.fill.background()

        tb = s7.shapes.add_textbox(cx + Inches(0.2), cy + Inches(0.12), Inches(5.38), Inches(2.35))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = color
        p.font.name = FONT_NAME

        for item in items:
            pi = tf.add_paragraph()
            pi.text = "• " + item
            pi.font.size = Pt(11)
            pi.font.color.rgb = TEXT_DARK
            pi.font.name = FONT_NAME
            pi.space_before = Pt(3)

    # =========================================================================
    # SLIDE 8: CONFIGURATION DRIFT ЖӘНЕ 1-CLICK ТҮЗЕТУ (CLEAN SCREENSHOT BOX)
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s8, "Configuration Drift және 1-Click Түзету механизмі", "DRIFT ЖӘНЕ REMEDIATION", 8)

    # Left text card
    d_card = add_white_card(s8, Inches(0.8), Inches(1.45), Inches(5.5), Inches(5.6))
    d_tb = s8.shapes.add_textbox(Inches(1.0), Inches(1.65), Inches(5.1), Inches(5.2))
    d_tf = d_tb.text_frame
    d_tf.word_wrap = True

    dp1 = d_tf.paragraphs[0]
    dp1.text = "Configuration Drift қалай туындайды?"
    dp1.font.size = Pt(14)
    dp1.font.bold = True
    dp1.font.color.rgb = SATBAYEV_BLUE
    dp1.font.name = FONT_NAME

    drifts = [
        "Тікелей ауытқу (Direct Drift): Terraform кодында SSH порты 10.0.0.0/8 жеке желісіне шектелген, бірақ әкімші оны AWS веб-консолі арқылы (ClickOps) 0.0.0.0/0-ге ашып қойған.",
        "Көлеңкелі инфрақұрылым (Shadow IT): Бұлтта пайда болған осал Security Group немесе RDS дерекқоры ұсынылған Terraform файлдарында мүлде сипатталмаған.",
        "1-Click Remediation мүмкіндігі: Табылған әрбір қауіп үшін жүйе дайын AWS CLI пәрменін немесе Terraform HCL код патчын ұсынады. Инженер қауіпті бір батырмамен түзей алады."
    ]
    for dr in drifts:
        p = d_tf.add_paragraph()
        p.text = "• " + dr
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_DARK
        p.font.name = FONT_NAME
        p.space_before = Pt(8)

    # Right Card: Clean Screenshot fitted with border
    r_card8 = add_white_card(s8, Inches(6.5), Inches(1.45), Inches(6.033), Inches(5.6))
    img_findings = os.path.join("d:\\Diplom", "06_cloudsec_auditor_vulnerable_findings.png")
    if os.path.exists(img_findings):
        s8.shapes.add_picture(img_findings, Inches(6.72), Inches(1.65), width=Inches(5.6))
    
    cap_tb = s8.shapes.add_textbox(Inches(6.72), Inches(6.32), Inches(5.6), Inches(0.6))
    cap_tf = cap_tb.text_frame
    cap_tf.word_wrap = True
    pc = cap_tf.paragraphs[0]
    pc.text = "Сурет: Веб-интерфейстегі Drift белгісі және автоматты түзету шешімдері"
    pc.font.size = Pt(10)
    pc.font.bold = True
    pc.font.color.rgb = SATBAYEV_BLUE
    pc.font.name = FONT_NAME

    # =========================================================================
    # SLIDE 9: ҚАУІПСІЗДІКТІ БАҒАЛАУ МАТЕМАТИКАЛЫҚ МОДЕЛІ
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s9, "Қауіпсіздік деңгейін бағалау моделі (Scoring)", "МАТЕМАТИКАЛЫҚ МОДЕЛЬ", 9)

    f_card = add_white_card(s9, Inches(0.8), Inches(1.45), Inches(5.75), Inches(5.6), border=CARD_BORDER_BLUE)
    f_tb = s9.shapes.add_textbox(Inches(1.0), Inches(1.65), Inches(5.35), Inches(5.2))
    f_tf = f_tb.text_frame
    f_tf.word_wrap = True

    fp1 = f_tf.paragraphs[0]
    fp1.text = "Математикалық есептеу алгоритмі"
    fp1.font.size = Pt(14)
    fp1.font.bold = True
    fp1.font.color.rgb = SATBAYEV_BLUE
    fp1.font.name = FONT_NAME

    f_items = [
        "Базалық сыйымдылық (Benchmark Capacity):\nCapacity = sum(2 * W_r) = 168 балл\n(3 CRITICAL x 20 + 5 HIGH x 14 + 4 MED x 8 + 3 LOW x 2 = 168)",
        "Уақытша айыппұл шегі (Diminishing Penalty):\nP_r = W_r * (1 + 0.25 * min(N_r - 1, 4))\nБір ереженің 10 рет қайталануы бағаны жасанды құлдыратпайды (макс. шегі 2 * W_r).",
        "Айыппұл пайызы және қорытынды балл:\nDeduction = (sum(P_r) / Capacity) * 100\nScore = max(0, min(100, 100 - round(Deduction)))"
    ]
    for it in f_items:
        p = f_tf.add_paragraph()
        p.text = it
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_DARK
        p.font.name = FONT_NAME
        p.space_before = Pt(8)

    g_card9 = add_white_card(s9, Inches(6.8), Inches(1.45), Inches(5.733), Inches(5.6), border=CARD_BORDER_BLUE)
    g_tb9 = s9.shapes.add_textbox(Inches(7.0), Inches(1.65), Inches(5.333), Inches(5.2))
    g_tf9 = g_tb9.text_frame
    g_tf9.word_wrap = True

    gp9 = g_tf9.paragraphs[0]
    gp9.text = "Рейтинг шкаласы және Critical Capping"
    gp9.font.size = Pt(14)
    gp9.font.bold = True
    gp9.font.color.rgb = ACCENT_AMBER
    gp9.font.name = FONT_NAME

    g_items = [
        "Қауіптілік салмақтары (Severity Weights):\n• CRITICAL: 10 балл\n• HIGH: 7 балл\n• MEDIUM: 4 балл\n• LOW: 1 балл",
        "Әріптік рейтинг шкаласы (Letter Grades):\n• 90 - 100 балл: Grade A (Мінсіз / Қорғалған)\n• 80 - 89 балл: Grade B (Жақсы деңгей)\n• 70 - 79 балл: Grade C (Орташа қауіп)\n• 60 - 69 балл: Grade D (Жоғары қауіп)\n• 0 - 59 балл: Grade F (Сыни қауіпті)",
        "Critical Capping қағидаты:\nЕгер кемінде бір CRITICAL қауіп қалса, жүйе балы 94 болса да, рейтинг «B» деңгейінен аспайды!"
    ]
    for git in g_items:
        p = g_tf9.add_paragraph()
        p.text = git
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_DARK
        p.font.name = FONT_NAME
        p.space_before = Pt(8)

    # =========================================================================
    # SLIDE 10: ТЕСТІЛЕУ ЖӘНЕ ЭКСПЕРИМЕНТ НӘТИЖЕЛЕРІ (CLEAN SCREENSHOT BOX)
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s10, "Тестілеу және салыстырмалы аудит нәтижелері", "ЭКСПЕРИМЕНТТІК НӘТИЖЕЛЕР", 10)

    t_card10 = add_white_card(s10, Inches(0.8), Inches(1.45), Inches(5.5), Inches(5.6))
    tb10 = s10.shapes.add_textbox(Inches(1.0), Inches(1.65), Inches(5.1), Inches(5.2))
    tf10 = tb10.text_frame
    tf10.word_wrap = True

    p10 = tf10.paragraphs[0]
    p10.text = "Салыстырмалы эксперимент динамикасы"
    p10.font.size = Pt(14)
    p10.font.bold = True
    p10.font.color.rgb = ACCENT_EMERALD
    p10.font.name = FONT_NAME

    exp_bullets = [
        "49/49 Бірлік тесттер (Pytest): 100% сәтті өтті (EC2, S3, IAM, Drift, Scoring, CLI, Negative Tests, API).",
        "Түзетуге дейінгі аудит:\n• 19 табылған қауіп (3 Critical, 8 High)\n• Скоринг бағасы: 49 / 100 балл\n• Рейтингі: Grade F (Сыни деңгей)",
        "Түзетуден кейінгі қайталама аудит:\n• Тек 1 қауіп сақталды (Root MFA)\n• Скоринг бағасы: 94 / 100 балл\n• Рейтингі: Grade B (Critical Capping әсері)",
        "Қорытынды тиімділік:\nЖүйе 18 осалдықты жойып, қауіпсіздік деңгейін 45 баллға арттырды."
    ]
    for b in exp_bullets:
        p = tf10.add_paragraph()
        p.text = "• " + b
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_DARK
        p.font.name = FONT_NAME
        p.space_before = Pt(6)

    r_card10 = add_white_card(s10, Inches(6.5), Inches(1.45), Inches(6.033), Inches(5.6))
    img_splash = os.path.join("d:\\Diplom", "06_cloudsec_auditor_splash_grade_a.png")
    if os.path.exists(img_splash):
        s10.shapes.add_picture(img_splash, Inches(6.72), Inches(1.75), width=Inches(5.6))
    
    tb_c10 = s10.shapes.add_textbox(Inches(6.72), Inches(5.7), Inches(5.6), Inches(1.1))
    tf_c10 = tb_c10.text_frame
    tf_c10.word_wrap = True
    pc10 = tf_c10.paragraphs[0]
    pc10.text = "Сурет: CloudSec Auditor 100 баллдық таза күйге қол жеткізу анимациясы (Grade A)"
    pc10.font.size = Pt(10.5)
    pc10.font.bold = True
    pc10.font.color.rgb = SATBAYEV_BLUE
    pc10.font.name = FONT_NAME

    # =========================================================================
    # SLIDE 11: ҒЫЛЫМИ ЖАҢАШЫЛДЫҚ: TRUSTGAP-CSPM МОДЕЛІ
    # =========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s11, "Ғылыми жаңашылдық: TrustGap-CSPM моделі", "ҒЫЛЫМИ ЖАҢАШЫЛДЫҚ", 11)

    tg_cards = [
        ("Уақыттық тәуекел интервалы", SATBAYEV_BLUE, [
            "Дәстүрлі сканерлер тек T_scan уақытындағы күйді көреді.",
            "Егер қауіп екі сканерлеу арасында ашылып, қайта жабылса, байқалмай қалады.",
            "TrustGap-CSPM: AWS Config жазбалары мен CloudTrail API оқиғаларын уақыт белгілері бойынша корреляциялайды."
        ]),
        ("STS сессияларының қалдық қаупі", ACCENT_AMBER, [
            "Әкімші IAM рөлінің сенім саясатын (Trust Policy) шектегенімен, бұрын берілген уақытша STS деректері күшінде қала береді.",
            "Модель сессиялардың берілу мерзімі мен нақты кері қайтарылуын (revoke) қадағалайды.",
            "Құқықтар өзгергеннен кейінгі қалдық қолжетімділік тәуекелін бағалайды."
        ]),
        ("Дәлелдемелік жіктеу", ACCENT_EMERALD, [
            "Бақыланған фактілер: CloudTrail логында тікелей тіркелген сәтті API шақырулары.",
            "Модельдік ықтималдық: Конфигурация бойынша орындалуы мүмкін болған қатынастар.",
            "Белгісіздік шектері: Деректер жетіспеген жағдайда жалған оң қорытынды жасаудан сақтайды."
        ])
    ]

    for i, (title, color, items) in enumerate(tg_cards):
        x = Inches(0.8 + i * 4.0)
        card = add_white_card(s11, x, Inches(1.45), Inches(3.7), Inches(5.6))
        
        top_bar = s11.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, Inches(1.45), Inches(3.7), Inches(0.08))
        top_bar.fill.solid()
        top_bar.fill.fore_color.rgb = color
        top_bar.line.fill.background()

        tb = s11.shapes.add_textbox(x + Inches(0.2), Inches(1.65), Inches(3.3), Inches(5.2))
        tf = tb.text_frame
        tf.word_wrap = True
        
        ph = tf.paragraphs[0]
        ph.text = title
        ph.font.size = Pt(14)
        ph.font.bold = True
        ph.font.color.rgb = color
        ph.font.name = FONT_NAME

        for item in items:
            p = tf.add_paragraph()
            p.text = "• " + item
            p.font.size = Pt(11)
            p.font.color.rgb = TEXT_DARK
            p.font.name = FONT_NAME
            p.space_before = Pt(8)

    # =========================================================================
    # SLIDE 12: ҚОРЫТЫНДЫ (CONCLUSION)
    # =========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    add_satbayev_header(s12, "Қорытынды және дипломдық жобаның құндылығы", "ҚОРЫТЫНДЫ", 12)

    c_card12 = add_white_card(s12, Inches(0.8), Inches(1.45), Inches(6.8), Inches(5.6))
    tb12 = s12.shapes.add_textbox(Inches(1.0), Inches(1.65), Inches(6.4), Inches(5.2))
    tf12 = tb12.text_frame
    tf12.word_wrap = True

    p12 = tf12.paragraphs[0]
    p12.text = "Дипломдық жобаның негізгі нәтижелері:"
    p12.font.size = Pt(15)
    p12.font.bold = True
    p12.font.color.rgb = SATBAYEV_BLUE
    p12.font.name = FONT_NAME

    achievements = [
        "1. Кешенді бұлттық сканер әзірленді: AWS ресурстары мен Terraform кодтарын бір мезгілде тексеретін CloudSec Auditor платформасы құрылды.",
        "2. Configuration Drift тетігі жүзеге асырылды: Live инфрақұрылым мен IaC арасындағы ауытқулар және Shadow IT ресурстары 1-Click түзетумен толықтырылды.",
        "3. Әділ салмақтық скоринг моделі жасалды: 168 сыйымдылықты, айыппұл шектеуі (diminishing penalty) және Critical capping бар математикалық жүйе құрылды.",
        "4. Жоғары сапамен тестіленді: 49 автоматты тест (100% pass) және модельдік ортада қауіпсіздік деңгейін 49-дан 94 баллға көтеру тәжірибесі расталды.",
        "5. TrustGap-CSPM моделі негізделді: Конфигурация тарихын, сенім саясаттарын және STS сессияларын уақыттық корреляциялау әдісі ұсынылды."
    ]
    for ach in achievements:
        p = tf12.add_paragraph()
        p.text = ach
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_DARK
        p.font.name = FONT_NAME
        p.space_before = Pt(6)

    r_card12 = add_white_card(s12, Inches(7.8), Inches(1.45), Inches(4.733), Inches(5.6), border=SATBAYEV_BLUE)
    
    top_bar12 = s12.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(7.8), Inches(1.45), Inches(4.733), Inches(0.08))
    top_bar12.fill.solid()
    top_bar12.fill.fore_color.rgb = SATBAYEV_BLUE
    top_bar12.line.fill.background()

    r_tb12 = s12.shapes.add_textbox(Inches(8.0), Inches(1.8), Inches(4.333), Inches(5.0))
    r_tf12 = r_tb12.text_frame
    r_tf12.word_wrap = True

    rp = r_tf12.paragraphs[0]
    rp.alignment = PP_ALIGN.CENTER
    rp.text = "НАЗАРЛАРЫҢЫЗҒА РАҚМЕТ!"
    rp.font.size = Pt(18)
    rp.font.bold = True
    rp.font.color.rgb = SATBAYEV_BLUE
    rp.font.name = FONT_NAME

    rp2 = r_tf12.add_paragraph()
    rp2.alignment = PP_ALIGN.CENTER
    rp2.text = "Сұрақтарыңыз болса, жауап беруге дайынбыз."
    rp2.font.size = Pt(12)
    rp2.font.color.rgb = TEXT_MUTED
    rp2.font.name = FONT_NAME
    rp2.space_before = Pt(12)

    rp3 = r_tf12.add_paragraph()
    rp3.alignment = PP_ALIGN.CENTER
    rp3.text = "\n----------------------------------------\nЖобаның ресми GitHub репозиторийі:\ngithub.com/sultanbek2024/cloud-security-scanner\n\nҚ.И. Сәтбаев атындағы ҚазҰТЗУ\nАлматы, 2026"
    rp3.font.size = Pt(11)
    rp3.font.color.rgb = SATBAYEV_BLUE
    rp3.font.name = FONT_NAME
    rp3.space_before = Pt(16)

    # Save outputs
    desktop_dir = os.path.join(os.environ['USERPROFILE'], 'Desktop')
    out_name = "Бұлттық инфрақұрылымның конфигурациялық осалдықтарын анықтау және қауіпсіздігін бағалау жүйесін әзірлеу.pptx"
    
    desktop_path = os.path.join(desktop_dir, out_name)
    local_path = os.path.join("d:\\Diplom", out_name)

    prs.save(desktop_path)
    prs.save(local_path)
    print("Successfully built Satbayev Light Theme Presentation!")
    print(f"Desktop: {desktop_path}")
    print(f"Local: {local_path}")

if __name__ == '__main__':
    build_satbayev_light_deck()
