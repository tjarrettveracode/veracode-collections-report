from __future__ import annotations
import sys
import argparse
import logging
import datetime
import os
import json

import anticrlf
from reportlab.pdfgen import canvas
from reportlab.lib import utils, colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.units import inch


from veracode_api_py import VeracodeAPI as vapi, Collections, Findings, Users

log = logging.getLogger(__name__)

# constants
title = 'Veracode Collection Report'
collection_name = ''
report_time = ''
username = ''
copyright_year = ''

width, height = letter
printable_width = 0
logo = os.path.join("resources", "veracode-black-hires.jpg")
spacer = Spacer(1, 0.5 * inch)

styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(name="Normal12", parent=styles["Normal"], fontSize=12), alias="n12"
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


def get_collection_information(collguid):
    collection_info = Collections().get(collguid)
    # assets = collection_info.get('asset_infos')
    assets = Collections().get_assets(collection_info.get('guid'))
    collection_info['asset_infos'] = assets
    applications = [asset['guid'] for asset in assets]
    findings_list = get_policy_violating_findings(applications)
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


def get_app_profile_summary_data(app_findings):
    app_summary_info = {}
    findingsbysev = {}
    findingsbysev['sev5'] = []
    findingsbysev['sev4'] = []
    findingsbysev['sev3'] = []
    findingsbysev['sev2'] = []
    findingsbysev['sev1'] = []
    findingsbysev['sev0'] = []
    for finding in app_findings:
        severity = finding["finding_details"]["severity"]
        severityStr = str(severity)
        if ('sev'+severityStr not in findingsbysev):
            findingsbysev['sev'+severityStr] = []
        findingsbysev['sev'+severityStr].append(finding)

    app_summary_info['findings_by_severity'] = findingsbysev
    app_summary_info['app_findings'] = app_findings
    return app_summary_info


def update_collection_findings_by_sev(collection_summary, app_findings_summary):
    collection_summary['sev5'] = collection_summary.get('sev5', []) + app_findings_summary.get('sev5', [])
    collection_summary['sev4'] = collection_summary.get('sev4', []) + app_findings_summary.get('sev4', [])
    collection_summary['sev3'] = collection_summary.get('sev3', []) + app_findings_summary.get('sev3', [])
    collection_summary['sev2'] = collection_summary.get('sev2', []) + app_findings_summary.get('sev2', [])
    collection_summary['sev1'] = collection_summary.get('sev1', []) + app_findings_summary.get('sev1', [])
    collection_summary['sev0'] = collection_summary.get('sev0', []) + app_findings_summary.get('sev0', [])
    return collection_summary


def get_policy_violating_findings(apps):
    status = "Getting findings for {} applications…".format(len(apps))
    print(status)
    log.info(status)
    collection_summary = {}
    all_findings = {}
    params = {"violates_policy": True}
    for app in apps:
        log.debug("Getting findings for application {}".format(app))
        this_app_findings = Findings().get_findings(app, request_params = params) # update to do by severity and policy status
        this_app_findings = get_app_profile_summary_data(this_app_findings)
        collection_summary = update_collection_findings_by_sev(collection_summary, this_app_findings['findings_by_severity'])
        all_findings[app] = this_app_findings

    all_findings['collection_summary'] = collection_summary
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


def summary_page(Story, collection_info):
    compliance_status = Collections().compliance_titles[collection_info.get('compliance_status').lower()]
    compliance_status_description = 'one or more assets did not pass policy'
    collection_description = collection_info.get('description')
    findings_list = collection_info.get('findings_list')
    findingsbysev = findings_list.pop('collection_summary')

    compliance_overview = collection_info.get('compliance_overview')

    sectionTitle = Paragraph("Executive Summary", styles["h1"])
    Story.append(sectionTitle)
    Story.append(spacer)

    summaryTableData = []
    summaryTableData.append(['Collection', collection_name])

    compliance_status_paragraph = Paragraph(compliance_status + "<br/><i>" + compliance_status_description + "</i>",styles['Normal'])
    summaryTableData.append(['Status', compliance_status_paragraph])

    summaryTableData.append(['Collection Description', collection_description])

    summaryTableData.append(['Assets', collection_info.get('total_assets')])
    summaryTable = Table(summaryTableData, [0.5 * printable_width, 0.5 * printable_width])
    tstyle = TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")])
    summaryTable.setStyle(tstyle)
    Story.append(summaryTable)

    Story.append(spacer)

    wrappperTableData = []

    complianceOverviewTableData = []
    complianceOverviewTableData.append([Paragraph('Compliance Overview', styles['h3']), ''])
    complianceOverviewTableData.append(['', ''])
    complianceOverviewTableData.append([Paragraph('Did Not Pass:'), compliance_overview['not_passing_policy']])
    complianceOverviewTableData.append([Paragraph('Passed:'), compliance_overview['passing_policy']])
    complianceOverviewTableData.append([Paragraph('Conditionally Pass:'), compliance_overview['conditionally_passing_policy']])
    complianceOverviewTableData.append([Paragraph('Not Assessed:'), compliance_overview['not_assessed']])
    complianceOverviewTable = Table(complianceOverviewTableData, [0.3 * printable_width, 0.1 * printable_width])
    complianceOverviewStyle = TableStyle(
        [("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (0, 0), (-1, -1), "RIGHT")]
    )
    complianceOverviewTable.setStyle(complianceOverviewStyle)
    complianceOverviewTable.hAlign = 'LEFT'

    openFindingsPolicyTable = findings_summary(findingsbysev)

    wrappperTableData.append([complianceOverviewTable, openFindingsPolicyTable])
    wrapperTable = Table(wrappperTableData, [0.5 * printable_width, 0.5 * printable_width])
    wrapperTableStyle = TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")])
    wrapperTable.setStyle(wrapperTableStyle)
    wrapperTable.hAlign = 'LEFT'
    Story.append(wrapperTable)
    Story.append(PageBreak())


def findings_summary(findingsbysev):
    openFindingsPolicyTableData = []
    openFindingsPolicyTableData.append([Paragraph('Open Findings Impacting Policy', styles['h3']), ''])
    openFindingsPolicyTableData.append(['', ''])
    openFindingsPolicyTableData.append([Paragraph('Very High Severity:'), len(findingsbysev['sev5'])])
    openFindingsPolicyTableData.append([Paragraph('High Severity:'), len(findingsbysev['sev4'])])
    openFindingsPolicyTableData.append([Paragraph('Medium Severity:'), len(findingsbysev['sev3'])])
    openFindingsPolicyTableData.append([Paragraph('Low Severity:'), len(findingsbysev['sev2'])])
    openFindingsPolicyTableData.append([Paragraph('Very Low Severity:'), len(findingsbysev['sev1'])])
    openFindingsPolicyTableData.append([Paragraph('Informational Severity:'), len(findingsbysev['sev0'])])
    openFindingsPolicyTable = Table(openFindingsPolicyTableData, [0.3 * printable_width, 0.1 * printable_width])
    openFindingsPolicyStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("SPAN", (0, 0), (1, 0)),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ]
    )
    openFindingsPolicyTable.setStyle(openFindingsPolicyStyle)
    openFindingsPolicyTable.hAlign = 'LEFT'
    return openFindingsPolicyTable


def asset_policy_evaluation_page(Story, collection_info):
    assets = collection_info.get('asset_infos')

    didnotpassicon = os.path.join("resources", "fail.png")
    conditionalicon = os.path.join("resources", "conditional.png")
    passicon = os.path.join("resources", "pass.png")
    notassessicon = os.path.join("resources", "notassessed.png")

    not_passed = collection_info['compliance_overview']['not_passing_policy']
    conditional = collection_info['compliance_overview']['conditionally_passing_policy']
    passed = collection_info['compliance_overview']['passing_policy']
    not_assessed = collection_info['compliance_overview']['not_assessed']

    sectionTitle = Paragraph("Asset Policy Evaluation", styles["h1"])
    Story.append(sectionTitle)
    Story.append(spacer)

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
    section_header = Paragraph(
        Collections().compliance_titles[compliance_type.upper()], styles["n12"]
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
            Paragraph("<b>Last Scan Date</b>"),
        ]
    )

    pass_icon = get_image(os.path.join("resources", "small", "pass.png"), 0.1 * inch)
    conditional_icon = get_image(os.path.join("resources", "small", "conditional.png"), 0.1 * inch)
    fail_icon = get_image(os.path.join("resources", "small", "fail.png"), 0.1 * inch)
    tableStyle = TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")])
    ps = styles['Normal']
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

    assetTable = Table(assetTableData, [0.3*printable_width, 0.25 * printable_width,0.25 * printable_width, 0.2 * printable_width])

    assetTable.setStyle(tableStyle)
    return assetTable


def profile_pages(Story, collection_info):
    findings_list = collection_info.get('findings_list')

    sectionTitle = Paragraph('Profile Summaries', styles['h1'])
    Story.append(sectionTitle)
    Story.append(spacer)
    for profile in findings_list:
        profile_summary_section(Story, findings_list[profile])
        profile_details_section(Story, findings_list[profile])


def profile_summary_section(Story, profile):
    summary_data = []
    pass_icon = os.path.join('resources', 'pass.png')
    conditional_icon = os.path.join('resources', 'conditional.png')
    fail_icon = os.path.join('resources', 'fail.png')
    not_assess_icon = os.path.join('resources', 'notassessed.png')
    asset_info = profile['asset_info']
    asset_attributes = asset_info['attributes']
    display_icon = not_assess_icon
    if (asset_attributes['policy_passed_scan_requirements']):
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
    titleCellTableData = []
    titleCellTableData.append([icon, profileName])
    titleCellTable = Table(titleCellTableData, [0.05 * printable_width, 0.9 * printable_width])
    titleCellTableStyle = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]
    )
    titleCellTable.setStyle(titleCellTableStyle)
    titleCellTable.hAlign = 'LEFT'

    summary_data.append(titleCellTable)
    summary_data.append(Spacer(1, .25*inch))
    summary_table = profile_summary_table(None, [asset_info])
    summary_data.append(summary_table)
    summary_data.append(Spacer(1, .25*inch))
    findings_summary_table = findings_summary(profile['findings_by_severity'])
    summary_data.append(findings_summary_table)
    Story.append(KeepTogether(summary_data))
    Story.append(Spacer(1, .25*inch))


def profile_details_section(Story, profile):
    profile_findings_data = []
    sectionTitle = Paragraph('Detailed Findings', styles['h4'])
    profile_findings_data.append(sectionTitle)
    profile_findings_data.append(Spacer(1, .25*inch))


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

    page_number = Paragraph("Page {}".format(doc.page), styles['hfr'])

    footerTableData.append([copyright_footer, page_number])    
    tstyle = TableStyle(
        [('ALIGN', (1, 0), (-1, -1), 'RIGHT')]
    )

    ft = Table(footerTableData, [0.8*doc.width, 0.2*doc.width])
    ft.setStyle(tstyle)
    _footer(canvas, doc, ft)

    # Release the canvas
    canvas.restoreState()


def write_report(collection_info):
    # cover page fields
    global collection_name 
    collection_name = collection_info.get('name')
    thisuser = get_self()
    global username
    username = thisuser.get('first_name') + ' ' + thisuser.get('last_name')
    global report_time
    today = datetime.datetime.now()
    report_time = today.strftime("%d/%m/%Y %H:%M:%S")
    global copyright_year 
    copyright_year = today.strftime("%Y")
    report_name = "Veracode Collection - {}.pdf".format(collection_name)

    doc = SimpleDocTemplate(report_name,
                            rightMargin=.5*inch,
                            leftMargin=.5*inch,
                            topMargin=72,
                            bottomMargin=72,)
    global printable_width
    printable_width = doc.width * 0.95
    Story = [spacer]

    cover_page(Story, username, report_time)

    summary_page(Story, collection_info)

    asset_policy_evaluation_page(Story, collection_info)

    profile_pages(Story, collection_info)

    # Enable to show page layout borders
    # doc.showBoundary = True 
    doc.build(Story, onFirstPage=coverPage, onLaterPages=otherPage)

    return report_name


def main():
    parser = argparse.ArgumentParser(
        description='This script lists modules in which static findings were identified.')
    parser.add_argument('-c', '--collectionsid', help='Collections guid to create a report', required=True)
    args = parser.parse_args()

    collguid = args.collectionsid
    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    status = "Getting asset data for collection {}...".format(collguid)
    log.info(status)
    print(status)
    this_collection = get_collection_information(collguid)

    # # write collection to local file for offline testing
    # with open("sample_collection.json", "w") as outfile:
    #     json.dump(this_collection, outfile)

    # Opening JSON file
    # with open('sample_collection.json', 'r') as openfile:
    #     # Reading from json file
    #     this_collection = json.load(openfile)

    report_name = write_report(this_collection)

    status = "Created report at {}".format(report_name)
    print(status)
    log.info(status)


if __name__ == '__main__':
    main()
