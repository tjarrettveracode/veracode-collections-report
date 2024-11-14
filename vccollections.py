from __future__ import annotations
import sys
import argparse
import logging
import datetime
import os
import json
import anticrlf
import csv
import math

from reportlab.lib import utils, colors
from reportlab.lib.colors import HexColor, PCMYKColor
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend


from veracode_api_py import VeracodeAPI as vapi, Collections, Findings, Users

log = logging.getLogger(__name__)

# constants
title = 'Veracode Collection Report'
collection_name = ''
report_time = ''
username = ''
copyright_year = ''

# veracode_blue_color = (CMYKColor(44, 5, 0, 19))
# veracode_blue_color = Color(45, 77, 81, 1)
veracode_blue_color = (HexColor('#74c4ce', htmlOnly=True))

printable_width = 0
logo = os.path.join("resources", "veracode-black-hires.jpg")
spacer = Spacer(1, 0.5 * inch)

styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(name="NormalBlue", parent=styles["Normal"], textColor=veracode_blue_color), alias="nb"
)
styles.add(
    ParagraphStyle(name="Heading1Blue", parent=styles["h1"], textColor=veracode_blue_color),
    alias="h1b",
)
styles.add(
    ParagraphStyle(name="Heading5Right", parent=styles["h5"], alignment=TA_RIGHT),
    alias="h5r",
)
styles.add(
    ParagraphStyle(name="HeaderFooter", parent=styles["Normal"], fontSize=6, leading=8),
    alias="hf",
)
styles.add(
    ParagraphStyle(name="HeaderFooterRight", parent=styles["hf"], alignment=TA_RIGHT),
    alias="hfr",
)

# ******************************* #
# Mapping
# ******************************* #
severity = {
    5: "Very High",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Very Low",
    0: "Informational",
}

severity_colors = (
    HexColor('#d13a85', htmlOnly=True),
    HexColor('#dc342e', htmlOnly=True),
    HexColor('#e99833', htmlOnly=True),
    HexColor('#f9ce42', htmlOnly=True),
    HexColor('#c8da3b', htmlOnly=True),
    HexColor('#90bc45', htmlOnly=True),
)

compliance_colors = (
    HexColor('#d4473b', htmlOnly=True),
    HexColor('#f68321', htmlOnly=True),
    HexColor('#3eb849', htmlOnly=True),
    HexColor('#cccccc', htmlOnly=True)
)

scan_type_names = {
    "STATIC": "Static",
    "DYNAMIC": "Dynamic",
    "SCA": "Software Composition Analysis",
    "MANUAL": "Manual Penetration Testing",
}

didnotpassicon = os.path.join("resources", "fail.png")
conditionalicon = os.path.join("resources", "conditional.png")
passicon = os.path.join("resources", "pass.png")
notassessicon = os.path.join("resources", "notassessed.png")


# ******************************* #
# Utilities
# ******************************* #


def roundup(x, multipleOf):
    if isinstance(x, int) or isinstance(x, float):
        x = int(x)
    if x == 0:
        return 0
    return math.ceil(x / multipleOf) * multipleOf


def get_icon_path_for_status(status):
    match status:
        case 'OUT_OF_COMPLIANCE':
            return didnotpassicon
        case 'WITHIN_GRACE_PERIOD':
            return conditionalicon
        case 'COMPLIANT':
            return passicon
        case _:
            return notassessicon

# ******************************* #
# Data collection section
# ******************************* #


def setup_logger():
    handler = logging.FileHandler('vccollections.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone()  #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])


def get_collection_information(collguid, scan_types, affects_policy):
    collection_info = Collections().get(collguid)
    assets = Collections().get_assets(collection_info.get('guid'))
    collection_info['asset_infos'] = assets
    applications = [asset['guid'] for asset in assets]
    findings_list = get_findings(applications, scan_types, affects_policy)
    collection_info['collection_summary'] = findings_list.pop('collection_summary')
    collection_info['collection_policy_summary'] = findings_list.pop('collection_policy_summary')
    for asset in assets:
        guid = asset.get('guid')
        if guid in findings_list and 'asset_info' not in findings_list.get(guid):
            finding = findings_list.get(guid)
            finding['asset_info'] = asset
    collection_info['findings_list'] = findings_list
    return collection_info


def get_self():
    return Users().get_self()


def get_collection_assets(collguid):
    return Collections().get_assets(collguid)


def get_finding_severity(finding):
    return finding['finding_details']['severity']


def get_app_profile_summary_data(app_findings):
    app_summary_info = {}
    allfindingsbysev = {}
    allfindingsbysev['sev5'] = []
    allfindingsbysev['sev4'] = []
    allfindingsbysev['sev3'] = []
    allfindingsbysev['sev2'] = []
    allfindingsbysev['sev1'] = []
    allfindingsbysev['sev0'] = []
    policyfindingsbysev = {}
    policyfindingsbysev['sev5'] = []
    policyfindingsbysev['sev4'] = []
    policyfindingsbysev['sev3'] = []
    policyfindingsbysev['sev2'] = []
    policyfindingsbysev['sev1'] = []
    policyfindingsbysev['sev0'] = []
    app_findings.sort(key=get_finding_severity, reverse=True)
    for finding in app_findings:
        severity = finding["finding_details"]["severity"]
        severityStr = str(severity)
        allfindingsbysev['sev'+severityStr].append(finding)
        if finding['violates_policy']:
            policyfindingsbysev['sev'+severityStr].append(finding)

    for findingSev in allfindingsbysev:
        allfindingsbysev[findingSev] = len(allfindingsbysev[findingSev])

    total_policy_findings = 0
    for policyFindingSev in policyfindingsbysev:
        findings_by_sev_lenth = len(policyfindingsbysev[policyFindingSev])
        policyfindingsbysev[policyFindingSev] = findings_by_sev_lenth
        total_policy_findings += findings_by_sev_lenth

    app_summary_info['findings_by_severity'] = allfindingsbysev
    app_summary_info['policy_findings_by_severity'] = policyfindingsbysev
    app_summary_info['total_findings'] = len(app_findings)
    app_summary_info['total_policy_findings'] = total_policy_findings
    app_summary_info['app_findings'] = app_findings
    return app_summary_info


def update_collection_findings_by_sev(collection_summary, app_findings_summary):
    collection_summary['sev5'] = collection_summary.get('sev5', 0) + app_findings_summary['sev5']
    collection_summary['sev4'] = collection_summary.get('sev4', 0) + app_findings_summary['sev4']
    collection_summary['sev3'] = collection_summary.get('sev3', 0) + app_findings_summary['sev3']
    collection_summary['sev2'] = collection_summary.get('sev2', 0) + app_findings_summary['sev2']
    collection_summary['sev1'] = collection_summary.get('sev1', 0) + app_findings_summary['sev1']
    collection_summary['sev0'] = collection_summary.get('sev0', 0) + app_findings_summary['sev0']
    return collection_summary


def get_findings(apps, scan_types_requested, affects_policy):
    status = "Getting findings for {} applications…".format(len(apps))
    print(status)
    log.info(status)
    collection_all_findings_summary = {}
    collection_policy_summary = {}
    all_findings = {}
    sca = False
    scan_types_to_get = list(scan_types_requested)
    if ('SCA' in scan_types_requested):
        sca = True
        scan_types_to_get.remove("SCA")
    params = {}
    if affects_policy:
        # params = {"violates_policy": True}
        params = {}
    for app in apps:
        this_app_SCA_findings = []
        log.debug("Getting findings for application {}".format(app))
        this_app_findings = Findings().get_findings(app, ','.join(scan_types_to_get), True, params)  # update to do by severity and policy status
        # SCA findings call must be made by itself currently. See official docs: https://docs.veracode.com/r/c_findings_v2_intro
        if sca:
            this_app_SCA_findings = Findings().get_findings(app, 'SCA', True)  # API does not accept violates_policy request parameter
        if len(this_app_SCA_findings) > 0:
            this_app_findings = this_app_findings + this_app_SCA_findings
        this_app_findings = get_app_profile_summary_data(this_app_findings)
        collection_all_findings_summary = update_collection_findings_by_sev(collection_all_findings_summary, this_app_findings['findings_by_severity'])
        collection_policy_summary = update_collection_findings_by_sev(collection_policy_summary, this_app_findings['policy_findings_by_severity'])
        all_findings[app] = this_app_findings

    all_findings['collection_summary'] = collection_all_findings_summary
    all_findings['collection_policy_summary'] = collection_policy_summary
    return all_findings

# ******************************* #
# PDF Generation section          #
# ******************************* #


def get_image(path, width=1 * inch):
    img = utils.ImageReader(path)
    iw, ih = img.getSize()
    aspect = ih / float(iw)
    return Image(path, width=width, height=(width * aspect))


def cover_page(Story, user_name, report_time):
    im = get_image(logo, 3*inch)
    Story.append(im)
    Story.append(spacer)

    titleStyle = styles['Title']
    Title = Paragraph("Collection Security Report", titleStyle)
    Story.append(Title)
    Story.append(spacer)

    style = styles['Normal']
    collection_name_p = Paragraph(
        "<b>Collection name:</b> {}".format(collection_name), style
    )
    Story.append(collection_name_p)
    prepared_by_p = Paragraph("<b>Prepared by:</b> {}".format(user_name), style)
    Story.append(prepared_by_p)
    date_p = Paragraph("<b>Date:</b> {}".format(report_time), style)
    Story.append(date_p)
    Story.append(spacer)

    tableData = []

    styleH5 = styles['h5']
    section = Paragraph("Sections", styleH5)
    page = Paragraph("Page", styles["h5r"])

    tableHeaders = [section, page]

    tableData.append(tableHeaders)

    tableData.append(['Executive Summary', '1'])
    tableData.append(['Asset Policy Evaluation', '2'])
    tableData.append(['Profile Summaries', '3'])

    tstyle = TableStyle(
        [
            ("LINEABOVE", (0, 0), (-1, 0), 2, colors.black),
            ("LINEBELOW", (0, 0), (-1, 0), 2, colors.black),
            ("LINEABOVE", (0, 2), (-1, -1), 0.25, colors.black),
            ("LINEBELOW", (0, -1), (-1, -1), 2, colors.black),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ]
    )

    t = Table(tableData, [0.9 * printable_width, 0.1 * printable_width])
    t.setStyle(tstyle)
    Story.append(t)
    Story.append(PageBreak())


def executive_summary_page(Story, collection_info):
    compliance_status = collection_info.get('compliance_status')
    compliance_status_text = Collections().compliance_titles[compliance_status.lower()]
    compliance_status_description = 'one or more assets did not pass policy'
    collection_description = collection_info.get('description')
    findingsbysev = collection_info['collection_summary']
    policyfindingsbysev = collection_info['collection_policy_summary']

    compliance_overview = collection_info.get('compliance_overview')

    ## Executive Summary Title
    sectionTitle = Paragraph("Executive Summary", styles["h1b"])
    titleLayoutTableData = []
    titleLayoutTableData.append([sectionTitle])
    titleLayoutTable = Table(titleLayoutTableData, [1 * printable_width])
    titleTableStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW", (0, -1), (-1, -1), 1.25, veracode_blue_color),
        ]
    )
    titleLayoutTable.setStyle(titleTableStyle)
    Story.append(titleLayoutTable)
    Story.append(Spacer(1, 0.125 * inch))

    ## Collection Summary section
    left_icon = get_icon_path_for_status(compliance_status)
    im = get_image(left_icon, .5*inch)

    ## Collection Summary wrapping layout table
    summaryLayoutTableData = []

    ## Collection Summary middle column table
    middle_collectionInfoTableData = []
    collection_title_style = ParagraphStyle('CollectionTitle', styles['nb'], fontSize=12)
    middle_collectionInfoTableData.append([Paragraph('Collection: ' + collection_name, collection_title_style)])

    tableBodyTextStyle = styles['BodyText']
    compliance_status_paragraph = Paragraph(
        "<b>Status: "
        + compliance_status_text
        + "</b><br/><i>"
        + compliance_status_description
        + "</i>",
        tableBodyTextStyle
    )
    middle_collectionInfoTableData.append([compliance_status_paragraph])

    middle_collectionInfoTableData.append([Paragraph('Collection Description: ' + collection_description, tableBodyTextStyle)])
    middle_collectionInfoTableData.append([Paragraph('Assets: ' + str(collection_info.get('total_assets')), tableBodyTextStyle)])
    middle_collectionInfoTable = Table(middle_collectionInfoTableData, [0.5 * printable_width])
    tMiddleStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (0, 1), 4),
            # ('INNERGRID', (0,1), (-1,-1), 0.25, colors.black),
        ]
    )
    middle_collectionInfoTable.setStyle(tMiddleStyle)

    ## Collection Summary right column table
    right_findingSummanyTableData = []
    total_findings = 0
    for sev in findingsbysev:
        total_findings += findingsbysev[sev]

    total_policy_findings = 0
    for sev in policyfindingsbysev:
        total_policy_findings += policyfindingsbysev[sev]
    normalRightStyle = ParagraphStyle(name="NormalRight", parent=styles["Normal"], alignment=TA_RIGHT)
    right_findingSummanyTableData.append([Paragraph('OPEN FINDINGS: ' + str(total_findings), normalRightStyle)])
    right_findingSummanyTableData.append([Paragraph('FINDINGS IMPACTING POLICY: ' + str(total_policy_findings), normalRightStyle)])

    right_findingSummanyTable = Table(right_findingSummanyTableData, [0.4 * printable_width])
    tRightStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]
    )
    right_findingSummanyTable.setStyle(tRightStyle)

    ## Collection Summary close and append layout table
    summaryLayoutTableData.append([im, middle_collectionInfoTable, right_findingSummanyTable])
    summaryLayoutTable = Table(summaryLayoutTableData, [0.1 * printable_width, 0.5 * printable_width, 0.4 * printable_width])
    tLayoutStyle = TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")])
    summaryLayoutTable.setStyle(tLayoutStyle)
    Story.append(summaryLayoutTable)
    Story.append(spacer)

    ## Overview Charts
    wrappperTableData = []

    complianceSummaryPieChart = compliance_summary_pie_chart(compliance_overview)
    openFindingsPolicyTable = findings_summary_chart(policyfindingsbysev)
    wrappperTableData.append([complianceSummaryPieChart, openFindingsPolicyTable])

    wrapperTable = Table(wrappperTableData, [0.5 * printable_width, 0.5 * printable_width], 0.7 * printable_width)
    wrapperTableStyle = TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")])
    wrapperTable.setStyle(wrapperTableStyle)
    wrapperTable.hAlign = 'LEFT'
    Story.append(wrapperTable)
    Story.append(PageBreak())


def compliance_summary_pie_chart(compliance_overview):
    fail = compliance_overview['not_passing_policy']
    conditional = compliance_overview['conditionally_passing_policy']
    passing = compliance_overview['passing_policy']
    not_assess = compliance_overview['not_assessed']
    compliance_data = [fail, conditional, passing, not_assess]
    total_assets = sum(compliance_data)

    d = Drawing(0.4 * printable_width, 0.35 * printable_width)

    pc = Pie()
    pc.x = -5
    pc.y = (0.35 * printable_width) / 4
    pc.width = 0.18 * printable_width
    pc.height = 0.18 * printable_width
    pc.data = compliance_data

    # Pie
    pc.simpleLabels = 0
    pc.strokeWidth = 0
    # Slices
    pc.slices.strokeWidth = 0.5
    pc.slices.strokeColor = PCMYKColor(0, 0, 0, 0)
    # Legend
    legend = Legend()
    legend.alignment = "right"
    legend.boxAnchor = "c"
    legend.x = 155
    legend.y = (0.35 * printable_width) / 2
    legend.columnMaximum = 99
    legend.dx = 6
    legend.dy = 6
    legend.dxTextSpace = 5
    legend.deltay = 10
    legend.strokeWidth = 0
    legend.strokeColor = None
    itemLabels = [
        (get_compliance_percent_string(fail, total_assets), " Did Not Pass"),
        (get_compliance_percent_string(conditional, total_assets), " Conditional Pass"),
        (get_compliance_percent_string(passing, total_assets), " Passed"),
        (get_compliance_percent_string(not_assess, total_assets), " Not Assessed"),
    ]
    items = []
    for i, color in enumerate(compliance_colors):
        items.append((color, itemLabels[i]))
        pc.slices[i].fillColor = color
    legend.colorNamePairs = items
    legend.subCols[1].align = "left"
    d.add(legend)
    d.add(pc)

    tableTitle = Paragraph('Compliance Overview', styles['h3'])
    wrappingTable = summary_table_wrap(d, tableTitle)

    return wrappingTable


def get_compliance_percent_string(current, total):
    return "{}%".format(str((current / total) * 100))


def findings_summary_chart(findingsbysev):

    openFindingsData = [
        (
            findingsbysev["sev5"],
            findingsbysev["sev4"],
            findingsbysev["sev3"],
            findingsbysev["sev2"],
            findingsbysev["sev1"],
            findingsbysev["sev0"],
        )
    ]

    drawing = Drawing(0.4 * printable_width, 0.35 * printable_width)
    bc = VerticalBarChart()
    bc.x = 0
    bc.y = 0.08 * printable_width
    bc.width = 0.4 * printable_width
    bc.height = 0.27 * printable_width
    bc.data = openFindingsData
    bc.strokeWidth = 0
    # bc.strokeColor = veracode_blue_color
    bc.barLabelFormat = "%s"
    bc.barLabels.nudge = 10
    # bc.barLabels.fontName        = fontName
    bc.barLabels.fontSize = 10
    bc.bars.strokeColor = None
    for i, color in enumerate(severity_colors):
        bc.bars[0, i].fillColor = color

    # Calculate step intervals and upper boundaries for chart
    max_value = 0
    for row in openFindingsData:
        new_max_value = max(row)
        max_value = max([new_max_value, max_value])
    step_interval = roundup(max_value, 10) / 5
    upper_bound = roundup(max_value, step_interval) + 35
    if upper_bound == 0:
        upper_bound = 100
    if step_interval == 0:
        step_interval = 10

    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = upper_bound
    bc.valueAxis.valueStep = step_interval
    # bc.valueAxis.labels.fontName = fontName
    # bc.valueAxis.labels.fontSize = 8
    bc.valueAxis.visible = 0
    # bc.valueAxis.rangeRound = "both"
    # bc.valueAxis.strokeWidth = 0
    # bc.valueAxis.visibleGrid = 0
    # bc.valueAxis.visibleTicks = 0
    # bc.valueAxis.visibleAxis = 0
    # bc.valueAxis.gridStrokeColor = PCMYKColor(100, 0, 46, 46)
    # bc.valueAxis.gridStrokeWidth = 0

    bc.categoryAxis.labels.boxAnchor = 'ne'
    bc.categoryAxis.labels.fontSize = 7
    bc.categoryAxis.labels.dx = 6
    bc.categoryAxis.labels.dy = -2
    bc.categoryAxis.labels.angle = 45
    bc.categoryAxis.visibleTicks = 0
    bc.categoryAxis.visibleAxis = 0
    bc.categoryAxis.categoryNames = [
        severity[5],
        severity[4],
        severity[3],
        severity[2],
        severity[1],
        severity[0],
    ]
    drawing.add(bc)
    tableTitle = Paragraph('Open Findings Impacting Policy', styles['h3'])
    wrappingTable = summary_table_wrap(drawing, tableTitle)
    return wrappingTable


def summary_table_wrap(drawing, tableTitle):
    wrappingTableData = []
    wrappingTableData.append([tableTitle])
    wrappingTableData.append([drawing])
    wrappingTable = Table(wrappingTableData, [0.45 * printable_width])
    wrappingTableStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOX", (0, 1), (-1, -1), 1.25, veracode_blue_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ]
    )
    wrappingTable.setStyle(wrappingTableStyle)
    wrappingTable.hAlign = 'LEFT'
    return wrappingTable


def asset_policy_evaluation_page(Story, collection_info):
    assets = collection_info.get('asset_infos')

    sectionTitle = Paragraph("Asset Policy Evaluation", styles["h1"])
    Story.append(sectionTitle)
    Story.append(spacer)

    not_passed = collection_info['compliance_overview']['not_passing_policy']
    conditional = collection_info['compliance_overview']['conditionally_passing_policy']
    passed = collection_info['compliance_overview']['passing_policy']
    not_assessed = collection_info['compliance_overview']['not_assessed']

    if not_passed > 0:
        # section - did not pass
        didnotpasstext = 'These assets have findings that violate policy rules and exceeded the remediation grace period or they have not been scanned at the required frequency.'
        asset_policy_evaluation_section(Story, 'DID_NOT_PASS', didnotpassicon, didnotpasstext, assets)

    if conditional > 0:
        # section - conditional
        conditionaltext = 'These assets have findings that violate policy rules and are within the remediation grace period and they have been scanned at the required frequency'
        asset_policy_evaluation_section(Story, 'CONDITIONAL_PASS', conditionalicon, conditionaltext, assets)

    if passed > 0:
        # section - passed
        passedtext = 'These assets passed all the aspects of the policy, including rules and required scans.'
        asset_policy_evaluation_section(Story, 'PASSED', passicon, passedtext, assets)

    if not_assessed > 0:
        # section - not assessed
        notassessedtext = 'These assets have not been scanned.'
        asset_policy_evaluation_section(Story, 'NOT_ASSESSED', notassessicon, notassessedtext, assets)
    Story.append(PageBreak())


def asset_policy_evaluation_section(Story, compliance_type, icon, descriptiontext, assets):
    headerStyle = ParagraphStyle(
        name="headerStyle", parent=styles["Normal"], fontSize=12
    )
    section_header = Paragraph(
        Collections().compliance_titles[compliance_type.upper()], headerStyle
    )
    sectionTitleTableData = []
    im = get_image(icon, .2*inch)
    sectionTitleTableData.append([im, section_header])
    sectionTitleTable = Table(sectionTitleTableData, [0.4*inch, 3*inch])
    sectionTitleTableStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]
    )
    sectionTitleTable.setStyle(sectionTitleTableStyle)
    sectionTitleTable.hAlign = 'LEFT'
    Story.append(sectionTitleTable)

    Story.append(Paragraph(descriptiontext))
    Story.append(Spacer(1, 0.25*inch))
    Story.append(profile_summary_table(compliance_type, assets))
    Story.append(spacer)


def profile_summary_table(compliance_type, assets):
    assetTableData = []
    assetTableData.append(
        [
            Paragraph("<b>Asset</b>"),
            Paragraph("<b>Rules</b>"),
            Paragraph("<b>Scan Requirements</b>"),
            Paragraph("<b>Last Scan Date</b>")
        ]
    )

    pass_icon = get_image(os.path.join("resources", "small", "pass.png"), 0.1 * inch)
    conditional_icon = get_image(os.path.join("resources", "small", "conditional.png"), 0.1 * inch)
    fail_icon = get_image(os.path.join("resources", "small", "fail.png"), 0.1 * inch)
    tableStyle = TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")])
    ps = styles['Normal']
    # ps.fontSize = 10
    for asset in assets:
        if asset["attributes"]["policies"][0]["policy_compliance_status"] == compliance_type or compliance_type is None:
            status_rules = asset['attributes'].get('policy_passed_rules')
            status_scan = asset['attributes'].get('policy_passed_scan_requirements')
            status_grace = asset['attributes'].get('policy_in_grace_period')
            scan_date = asset['attributes'].get('last_completed_scan_date')
            if status_rules:
                rules_icon = pass_icon
                rules_text = Paragraph('Passed', ps)
            elif status_grace:
                rules_icon = conditional_icon
                rules_text = Paragraph('Within Grace Period', ps)
            else:
                rules_icon = fail_icon
                rules_text = Paragraph('Did Not Pass', ps)
            if status_scan:
                scan_icon = pass_icon
                scan_text = Paragraph('Passed', ps)
            else:
                scan_icon = fail_icon
                scan_text = Paragraph('Did Not Pass', ps)

            if scan_date:                
                date_unfiltered = scan_date
                datetimeobj = datetime.datetime.strptime(date_unfiltered, '%Y-%m-%dT%H:%M:%S.%f%z')
                date_text = Paragraph(datetime.datetime.strftime(datetimeobj, '%m-%d-%Y %H:%M'), ps) 
            else:
                date_text = Paragraph('Not Scanned', ps)

            rulesCellTableData = []
            rulesCellTableData.append([rules_icon, rules_text])
            rulesCellTable = Table(rulesCellTableData, [0.03 * printable_width, 0.22 * printable_width])
            rulesCellTableStyle = TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
            rulesCellTable.setStyle(rulesCellTableStyle)

            scanCellTableData = []
            scanCellTableData.append([scan_icon, scan_text])
            scanCellTable = Table(scanCellTableData, [0.03 * printable_width, 0.22 * printable_width])
            scanCellTableStyle = TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
            scanCellTable.setStyle(scanCellTableStyle)
            assetName = Paragraph(asset['name'], ps)
            assetTableData.append([assetName, rulesCellTable, scanCellTable, date_text])

    assetTable = Table(assetTableData, [0.3*printable_width, 0.25 * printable_width, 0.25 * printable_width, 0.2 * printable_width])

    assetTable.setStyle(tableStyle)
    return assetTable


def profile_pages(Story, collection_info):
    findings_list = collection_info.get('findings_list')

    sectionTitle = Paragraph('Profile Summaries', styles['h1'])
    Story.append(sectionTitle)
    Story.append(spacer)
    for profile in findings_list:
        if profile != 'collection_summary':
            profile_summary_section(Story, findings_list[profile])
            profile_details_section(Story, findings_list[profile])
            Story.append(PageBreak())


def profile_summary_section(Story, profile):
    summary_data = []
    pass_icon = os.path.join('resources', 'pass.png')
    conditional_icon = os.path.join('resources', 'conditional.png')
    fail_icon = os.path.join('resources', 'fail.png')
    not_assess_icon = os.path.join('resources', 'notassessed.png')
    asset_info = profile['asset_info']
    asset_attributes = asset_info['attributes']
    display_icon = not_assess_icon
    if (asset_attributes['last_completed_scan_date'] is None):
        display_icon = not_assess_icon
    elif (asset_attributes['policy_passed_scan_requirements']):
        if (asset_attributes['policy_passed_rules']):
            display_icon = pass_icon
        elif (asset_attributes['policy_in_grace_period']):
            display_icon = conditional_icon
        else:
            display_icon = fail_icon
    else:
        display_icon = fail_icon
    icon = get_image(display_icon, .2*inch)
    profileName = Paragraph(profile['asset_info']['name'], styles['h3'])
    policyName = asset_attributes['policies'][0]['name']
    policy = Paragraph('<b>Policy:</b> {}'.format(policyName), styles['Normal'])
    titleCellTableData = []
    titleCellTableData.append([icon, profileName, policy])
    titleCellTable = Table(titleCellTableData, [0.05 * printable_width, 0.4 * printable_width, 0.5 * printable_width])
    titleCellTableStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
        ]
    )
    titleCellTable.setStyle(titleCellTableStyle)
    titleCellTable.hAlign = 'LEFT'

    summary_data.append(titleCellTable)
    summary_data.append(Spacer(1, .25*inch))
    summary_table = profile_summary_table(None, [asset_info])
    summary_data.append(summary_table)
    summary_data.append(Spacer(1, .25*inch))
    findings_summary_table = findings_summary_chart(profile['findings_by_severity'])
    summary_data.append(findings_summary_table)
    Story.append(KeepTogether(summary_data))
    Story.append(Spacer(1, .25*inch))


def profile_details_section(Story, profile):
    findings = profile['app_findings']
    if len(findings) > 0:
        sectionTitle = Paragraph('Detailed Findings', styles['h3'])
        Story.append(sectionTitle)
        Story.append(Spacer(1, .25*inch))
        findingsTableArray = {}
        for f in findings:
            scan_type = f['scan_type']
            data_row = []
            if (findingsTableArray.get(scan_type) is None):
                findingsTableArray[scan_type] = []
            match scan_type:
                case "STATIC":
                    data_row = static_findings_data_row(f)
                case 'DYNAMIC':
                    data_row = dyanmic_findings_data_row(f)
                case 'SCA':
                    data_row = sca_findings_data_row(f)
                case 'MANUAL':
                    data_row = manual_findings_data_row(f)
            if len(data_row) > 0:
                findingsTableArray[scan_type].append(data_row)
        for scan_type in findingsTableArray:
            if (len(findingsTableArray[scan_type]) > 1):
                findingTable = findings_table_generation(findingsTableArray[scan_type], scan_type)
                Story.append(findingTable)
                Story.append(Spacer(1, .25*inch))
        Story.append(Spacer(1, .25*inch))


def wrap_row_data(rowData, bold):
    lead_text = ''
    trail_text = ''
    if bold:
        lead_text = '<b>'
        trail_text = '</b>'
    new_row_data = []
    for item in rowData:
        if isinstance(item, int) or isinstance(item, float):
            item = str(item)
        new_row_data.append(Paragraph(lead_text+item+trail_text))
    return new_row_data


def static_findings_table_headers():
    staticTableHeaders = [
                "Flaw Id",
                "Severity",
                "CWE #",
                "CWE Name",
                "File Path/Name",
                "Line #",
                "Status",
                "Resolution"
            ]
    return [wrap_row_data(staticTableHeaders, True)]


def dynamic_findings_table_headers():
    dynamicTableHeaders = [
                "Flaw Id",
                "Severity",
                "CWE #",
                "CWE Name",
                "Path",
                "Vulnerable Parameter",
                "Status",
                "Resolution"
            ]
    return [wrap_row_data(dynamicTableHeaders, True)]


def sca_findings_table_headers():
    scaTableHeaders = [
                "CWE #",
                "CWE Name",
                "CVE #",
                "CVSS",
                "Severity",
                "Component Name",
                "Version",
                "Status",
                "Resolution"
            ]
    return [wrap_row_data(scaTableHeaders, True)]


def manual_findings_table_headers():
    manualTableHeaders = [
                "Flaw Id",
                "Severity",
                "CWE #",
                "CWE Name",
                "Input Vector",
                "Description",
                "Status",
                "Resolution"
            ]
    return [wrap_row_data(manualTableHeaders, True)]


def static_findings_data_row(f):
    data_row = [
        f.get('issue_id', ''),
        severity[f['finding_details']['severity']],
        f['finding_details']['cwe']['id'],
        f['finding_details']['cwe']['name'],
        f['finding_details'].get('file_path', ''),
        f['finding_details'].get('file_line_number', ''),
        f['finding_status']['status'].capitalize(),
        f['finding_status']['resolution'].capitalize()
    ]
    return wrap_row_data(data_row, False)


def dyanmic_findings_data_row(f):
    data_row = [
        f.get('issue_id', ''),
        severity[f['finding_details']['severity']],
        f['finding_details']['cwe']['id'],
        f['finding_details']['cwe']['name'],
        f['finding_details'].get('path', ''),
        f['finding_details'].get('vulnerable_parameter', ''),
        f['finding_status']['status'].capitalize(),
        f['finding_status']['resolution'].capitalize()
    ]
    return wrap_row_data(data_row, False)


def sca_findings_data_row(f):
    data_row = [
        f['finding_details'].get('cwe', {}).get('id', ''),
        f['finding_details'].get('cwe', {}).get('name', ''),
        f['finding_details']['cve']['name'],
        f['finding_details']['cve']['cvss'],
        severity[f['finding_details']['severity']],
        f['finding_details'].get('component_filename', ''),
        f['finding_details'].get('version', ''),
        f['finding_status']['status'].capitalize(),
        f['finding_status']['resolution'].capitalize()
    ]
    return wrap_row_data(data_row, False)


def manual_findings_data_row(f):
    data_row = [
        f.get('issue_id', ''),
        severity[f['finding_details']['severity']],
        f['finding_details']['cwe']['id'],
        f['finding_details']['cwe']['name'],
        f['finding_details'].get('input_vector', ''),
        f['description'],
        f['finding_status']['status'].capitalize(),
        f['finding_status']['resolution'].capitalize()
    ]
    return wrap_row_data(data_row, False)


def get_column_widths_for_scan_type(scan_type):
    pw = printable_width
    match scan_type:
        case "STATIC":
            return [
                0.08 * pw,  # Flaw ID
                0.12 * pw,  # Severity
                0.08 * pw,  # CWE #
                0.25 * pw,  # CWE Name
                0.15 * pw,  # File Path
                0.08 * pw,  # Line #
                0.1 * pw,  # Status
                0.14 * pw,  # Resolution
            ]
        case "DYNAMIC":
            return [
                0.08 * pw,  # Flaw ID
                0.12 * pw,  # Severity
                0.08 * pw,  # CWE #
                0.25 * pw,  # CWE Name
                0.11 * pw,  # Path
                0.1 * pw,  # Vulnerable Parameter
                0.1 * pw,  # Status
                0.14 * pw,  # Resolution
            ]
        case "SCA":
            return [
                0.08 * pw,  # CWE #
                0.15 * pw,  # CWE Name
                0.1 * pw,  # CVE #
                0.08 * pw,  # CVSS Score
                0.12 * pw,  # Severity
                0.13 * pw,  # Component Name
                0.1 * pw,  # Version
                0.1 * pw,  # Status
                0.14 * pw,  # Resolution
            ]
        case "MANUAL":
            return [
                0.08 * pw,  # Flaw ID
                0.12 * pw,  # Severity
                0.08 * pw,  # CWE #
                0.11 * pw,  # CWE Name
                0.1 * pw,  # Input Vector
                0.27 * pw,  # Description
                0.1 * pw,  # Status
                0.15 * pw,  # Resolution
            ]
        case _:
            return [
                0.08 * pw,  # Flaw ID
                0.12 * pw,  # Severity
                0.05 * pw,  # CWE #
                0.3 * pw,  # CWE Name
                0.2 * pw,  # File Path
                0.1 * pw,  # Line #
                0.1 * pw,  # Status
                0.14 * pw,  # Resolution
            ]


def get_table_header_for_scan_type(scan_type):
    match scan_type:
        case "STATIC":
            return static_findings_table_headers()
        case "DYNAMIC":
            return dynamic_findings_table_headers()
        case "SCA":
            return sca_findings_table_headers()
        case "MANUAL":
            return manual_findings_table_headers()
        case _: return []


def findings_table_generation(findingTableData, scan_type):
    tableTitle = Paragraph('Detailed ' + scan_type_names[scan_type] + ' Findings', styles['h4'])
    tableHeaders = get_table_header_for_scan_type(scan_type)
    column_widths = get_column_widths_for_scan_type(scan_type)
    scan_findings_table_array = [[tableTitle]] + tableHeaders + findingTableData
    tableStyle = TableStyle(
        [
            ("SPAN", (0, 0), (-1, 0)),
            ("ALIGNMENT", (0, 0), (-1, 0), "CENTER"),
            ("BOX", (0, 0), (-1, 0), 1, colors.black),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )    
    findingTable = Table(
        scan_findings_table_array,
        column_widths,
        None,
        tableStyle,
        2,
    )
    return findingTable


def _header(canvas, doc, content):
    # Header
    header = content
    w, h = header.wrap(doc.width, doc.topMargin)
    header.drawOn(canvas, doc.leftMargin, doc.height + doc.topMargin + h)


def _footer(canvas, doc, content):
    # Footer
    footer = content
    w, h = footer.wrap(doc.width, doc.bottomMargin)
    footer.drawOn(canvas, doc.leftMargin, h+40)


def coverPage(canvas, doc):
    # Save the state of our canvas so we can draw on it
    canvas.saveState()
    copyright = "Copyright {} Veracode, Inc. <br/><br/>While every precaution has been taken in the preparation of this document, Veracode, Inc. assumes no responsibility for errors, omissions, or for damages resulting from the use of the information herein. The Veracode Platform uses static and/or dynamic analysis techniques to discover potentially exploitable flaws. Due to the nature of software security testing, the lack fof discoverable flaws does not mean the software is 100 percent secure".format(copyright_year)
    copyright_footer = Paragraph(copyright, styles['hf'])
    footerTableData = []

    footerTableData.append([copyright_footer])    
    tstyle = TableStyle(
        [('ALIGN', (1, 0), (-1, -1), 'LEFT')]
    ) 

    ft = Table(footerTableData, [doc.width])
    ft.setStyle(tstyle)
    _footer(canvas, doc, ft)

    # Release the canvas
    canvas.restoreState()


def otherPage(canvas, doc):
    # Save the state of our canvas so we can draw on it
    canvas.saveState()
    headerTableData = []

    collection = Paragraph("Collection: {}".format(collection_name), styles['hf'])
    im = get_image(logo, .75*inch)
    headerTableData.append([collection, im])    
    tstyle = TableStyle([("ALIGN", (1, 0), (-1, -1), "RIGHT")])

    ht = Table(headerTableData, [0.5 * doc.width, 0.5 * doc.width])
    ht.setStyle(tstyle)
    _header(canvas, doc, ht)

    copyright_footer = Paragraph(
        "Copyright {} Veracode Inc.    Prepared {}     {} and Veracode Confidential".format(
            copyright_year, username, report_time
        ),
        styles["hf"],
    )
    footerTableData = []

    page_number = Paragraph("Page {}".format(doc.page - 1), styles['hfr'])

    footerTableData.append([copyright_footer, page_number])    
    tstyle = TableStyle(
        [('ALIGN', (1, 0), (-1, -1), 'RIGHT')]
    )

    ft = Table(footerTableData, [0.8*doc.width, 0.2*doc.width])
    ft.setStyle(tstyle)
    _footer(canvas, doc, ft)

    # Release the canvas
    canvas.restoreState()


def write_pdf_report(collection_info, report_name, landscape_orientation):
    # cover page fields
    page_size = letter
    if landscape_orientation:
        page_size = landscape(page_size)
    doc = SimpleDocTemplate(report_name,
                            rightMargin=.5*inch,
                            leftMargin=.5*inch,
                            topMargin=72,
                            bottomMargin=72,
                            pagesize=page_size)
    global printable_width
    printable_width = doc.width * 0.95
    Story = [spacer]

    cover_page(Story, username, report_time)

    executive_summary_page(Story, collection_info)

    asset_policy_evaluation_page(Story, collection_info)

    profile_pages(Story, collection_info)

    # Enable to show page layout borders
    # doc.showBoundary = True 
    doc.build(Story, onFirstPage=coverPage, onLaterPages=otherPage)

# ******************************* #
# CSV Generation section          #
# ******************************* #


def write_csv_report(collection_info, csvFilename):

    # writing to csv file
    with open(csvFilename, 'w') as csvfile:
        # creating a csv writer object
        csvwriter = csv.writer(csvfile)

        header_fields = [
            "Profile Name",
            "Flaw Id",
            "Scan Type",
            "Severity",
            "CWE Id",
            "CWE Name",
            "File Path/Name",
            "Line Number",
            "Path",
            "Vulnerable Parameter",
            "CVE #",
            "CVE Name",
            "SCA Component Name",
            "SCA Version",
            "Input Vector",
            "MPT  Description",
            "Status",
            "Resolution"
        ]
        # writing the fields
        csvwriter.writerow(header_fields)
        # writing the data rows
        findings_list = collection_info['findings_list']
        data_rows = []

        for profile in findings_list:
            if profile != "collection_summary":
                profileData = findings_list[profile]
                app_findings = profileData["app_findings"]
                for ap in app_findings:
                    data_row = [
                        profileData["asset_info"]["name"],
                        str(ap.get("issue_id", '')),
                        ap["scan_type"].capitalize(),
                        severity[ap["finding_details"]["severity"]],
                        str(ap["finding_details"].get("cwe", {}).get("id", "")),
                        ap["finding_details"].get("cwe", {}).get("name", ""),
                        ap["finding_details"].get("file_path", ""),
                        str(ap["finding_details"].get("file_line_number", "")),
                        ap["finding_details"].get("path", ""),
                        ap["finding_details"].get("vulnerable_parameter", ""),
                        str(ap["finding_details"].get("cve", {}).get("id", "")),
                        ap["finding_details"].get("cve", {}).get("name", ""),
                        ap["finding_details"].get("component_filename", ""),
                        ap["finding_details"].get("version", ""),
                        ap["finding_details"].get("input_vector", ""),
                        ap.get("description", ""),
                        ap["finding_status"]["status"].capitalize(),
                        ap["finding_status"]["resolution"].capitalize(),
                    ]
                    data_rows.append(data_row)
        csvwriter.writerows(data_rows)


def list_of_strings(choices):
    """Return a function that splits and checks comma-separated values."""

    def splitarg(arg):
        values = arg.split(",")
        for value in values:
            if value not in choices:
                raise argparse.ArgumentTypeError(
                    "invalid choice: {!r} (choose from {})".format(
                        value, ", ".join(map(repr, choices))
                    )
                )
        return values

    return splitarg


def main():
    format_choices = ["pdf", "csv", "json"]
    scan_type_choices = ["STATIC", "DYNAMIC", "SCA", "MANUAL"]

    parser = argparse.ArgumentParser(
        description="This script lists modules in which static findings were identified."
    )
    parser.add_argument(
        "-c",
        "--collectionsid",
        help="Collections guid to create a report",
        required=True,
    )
    parser.add_argument(
        "-f",
        "--format",
        type=list_of_strings(format_choices),
        default=['pdf'],
        help="Comma separate list of desired output formats. pdf (default), csv, json",
        required=False,
    )
    parser.add_argument(
        "-l",
        "--landscape",
        help="Print PDF in landscape orientation",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "-st",
        "--scan_types",
        type=list_of_strings(scan_type_choices),
        default=["STATIC", "DYNAMIC", "SCA", "MANUAL"],
        help="Comma separate list of desired scans to include, defaults to all options. options: STATIC, DYNAMIC, SCA, MANUAL",
        required=False,
    )
    parser.add_argument(
        "-p",
        "--policy",
        help="Only include findings that impact defined policy.",
        required=False,
        action="store_true",
    )
    args = parser.parse_args()
    collguid = args.collectionsid
    format = args.format
    scan_types = args.scan_types
    affects_policy = args.policy
    landscape_orientation = args.landscape

    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    status = "Getting asset data for collection {}...".format(collguid)
    log.info(status)
    print(status)
    collection_info = get_collection_information(collguid, scan_types, affects_policy)

    # Opening JSON file - Use for local testing to skip api calls
    # with open('sample_collection.json', 'r') as openfile:
    #     # Reading from json file
    #     collection_info = json.load(openfile)

    global collection_name
    collection_name = collection_info.get('name')
    thisuser = get_self()
    global username
    username = thisuser.get('first_name') + ' ' + thisuser.get('last_name')
    global report_time
    today = datetime.datetime.now()
    report_time = today.strftime("%d/%m/%Y %H:%M:%S")

    filename_time = ' - ' + today.strftime("%Y-%m-%d %H-%M-%S")
    filename_time = ''  # uncomment to output without date/time in filename
    global copyright_year
    copyright_year = today.strftime("%Y")

    outputFilename = "Veracode Collection - {}{}".format(collection_name, filename_time)
    print(outputFilename)
    log.info(outputFilename)

    # write collection to local file for offline testing
    if 'json' in format:
        jsonFilename = outputFilename+".json"
        with open(jsonFilename, "w") as outfile:
            json.dump(collection_info, outfile)
        jsonLog = "Wrote JSON file: {}".format(jsonFilename)
        print(jsonLog)
        log.info(jsonLog)

    if 'pdf' in format:
        pdfFilename = outputFilename+".pdf"
        write_pdf_report(collection_info, pdfFilename, landscape_orientation)
        jsonLog = "Wrote PDF file: {}".format(pdfFilename)
        print(jsonLog)
        log.info(jsonLog)

    if 'csv' in format:
        csvFilename = outputFilename+".csv"
        write_csv_report(collection_info, csvFilename)
        jsonLog = "Wrote CSV file: {}".format(csvFilename)
        print(jsonLog)
        log.info(jsonLog)

    status = "Reports generated for {}".format(outputFilename)
    print(status)
    log.info(status)


if __name__ == '__main__':
    main()
