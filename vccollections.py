import sys
import argparse
import logging
import datetime
import os

import anticrlf
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import Flowable

from veracode_api_py import VeracodeAPI as vapi, Collections, Findings, Users

log = logging.getLogger(__name__)

#constants

fontfamily = 'Helvetica'
fontbold = 'Helvetica-Bold' 
fontitalic = 'Helvetica-Oblique'
leftmargin = 36
titlesize = 30
h1size = 24
h2size = 12
normalsize = 10
lineheight = 1.5
smallprint = 6
width, height = letter
logo = os.path.join('resources','veracode-black-hires.jpg')

def setup_logger():
    handler = logging.FileHandler('vccollections.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def get_collection(collguid):
    return Collections().get(collguid)

def get_self():
    return Users().get_self()

def get_collection_assets(collguid):
    return Collections().get_assets(collguid)

def get_policy_violating_findings(apps):
    status = "Getting findings for {} applications…".format(len(apps))
    print(status)
    log.info(status)

    all_findings = []
    params = {"violates_policy": True}
    for app in apps:
        log.debug("Getting findings for application {}".format(app))
        this_app_findings = Findings().get_findings(app, request_params = params) # update to do by severity and policy status
        all_findings += this_app_findings

    findingsbysev = {}
    findingsbysev['sev5'] = len([finding for finding in all_findings if (finding["finding_details"]["severity"] == 5)])
    findingsbysev['sev4'] = len([finding for finding in all_findings if (finding["finding_details"]["severity"] == 4)])
    findingsbysev['sev3'] = len([finding for finding in all_findings if (finding["finding_details"]["severity"] == 3)])
    findingsbysev['sev2'] = len([finding for finding in all_findings if (finding["finding_details"]["severity"] == 2)])
    findingsbysev['sev1'] = len([finding for finding in all_findings if (finding["finding_details"]["severity"] == 1)])
    findingsbysev['sev0'] = len([finding for finding in all_findings if (finding["finding_details"]["severity"] == 0)])

    return findingsbysev


def write_header(pdf,collection_name):
    pdf.setFont(fontfamily,smallprint)
    pdf.drawString(leftmargin, height - 50, "Collection: {}".format(collection_name))
    pdf.drawImage(logo,width - 100, height - 50, 50,8 )
    
def write_footer(pdf, username, report_time, page_number):
    pdf.setFont(fontfamily,smallprint)
    pdf.drawString(leftmargin, 50, "Copyright 2021 Veracode Inc.    Prepared {}     {} and Veracode Confidential".format(username,report_time))
    pdf.drawString(width - 50, 50, str(page_number))

def write_multiple_strings(pdf, startx, starty, fontfamily, size, strings=[]):
    # iterates over a number of strings and writes to the page; returns a line count that you can add to the value of starty for the next line
    # (yes this is a poor man's flowable)

    pdf.saveState()
    pdf.setFont(fontfamily, size)
    counter = 0
    for string in strings:
        pdf.drawString(startx, starty - (counter*lineheight*size), string)
        counter += 1

    pdf.restoreState()

    return (counter+1)

def write_cover_page(pdf, collection_name, user_name, report_time):
    pdf.setFont(fontbold,titlesize)
    pdf.drawImage(logo,leftmargin,height - 100, 220, 33)

    pdf.drawString(leftmargin, height - 144, "Collection Security Report")
    pdf.setFont(fontfamily,normalsize)
    pdf.drawString(leftmargin, height - (144+(2 * lineheight * normalsize)), collection_name)
    pdf.drawString(leftmargin, height - (144+(3 * lineheight * normalsize)), user_name)
    pdf.drawString(leftmargin, height - (144+(4 * lineheight * normalsize)), report_time)

    pdf.setFont(fontbold, normalsize)
    pdf.drawString(leftmargin, height - (144+(8 * lineheight * normalsize)), 'Sections')
    pdf.drawString(leftmargin + 300, height - (144+(8 * lineheight * normalsize)), 'Page')

    pdf.setFont(fontfamily, normalsize)
    pdf.drawString(leftmargin, height - (144+(10 * lineheight * normalsize)), 'Executive Summary')
    pdf.drawString(leftmargin + 300, height - (144+(10 * lineheight * normalsize)), '1')
    pdf.drawString(leftmargin, height - (144+(11 * lineheight * normalsize)), 'Asset Policy Evaluation')
    pdf.drawString(leftmargin + 300, height - (144+(11 * lineheight * normalsize)), '2')

    pdf.setFont(fontfamily, smallprint)
    pdf.drawString(leftmargin, 144, "Copyright 2021 Veracode, Inc.")
    pdf.drawString(leftmargin, 144 - (2 * lineheight * smallprint), "{} and Veracode Confidential".format(user_name ))
    pdf.drawString(leftmargin, 144 - (3 * lineheight * smallprint), "While every precaution has been taken in the preparation of this document, " +
        "Veracode, Inc. assumes no responsibility for errors, omissions, or for damages resulting from the use of the information herein. ")
    pdf.drawString(leftmargin, 144 - (4 * lineheight * smallprint), "The Veracode Platform uses static and/or dynamic analysis techniques to discover " +
        "potentially exploitable flaws. Due to the nature of software security testing, the lack fof discoverable flaws does not mean" )
    pdf.drawString(leftmargin, 144 - (5 * lineheight * smallprint), "the software is 100 percent secure." )
    pdf.showPage()


def write_summary(pdf, collection_info, username, report_time):
    column2 = 300

    compliance_status = Collections().compliance_titles[collection_info.get('compliance_status').lower()]
    compliance_status_description = 'one or more assets did not pass policy'
    collection_description = collection_info.get('description')
    assets = collection_info.get('asset_infos')
    compliance_overview = collection_info.get('compliance_overview')
    applications = [asset['guid'] for asset in assets]
    findingsbysev = get_policy_violating_findings(applications)

    write_header(pdf,collection_info.get('name'))

    pdf.setFont(fontfamily,h1size)
    pdf.drawString(leftmargin, height - 100, "Executive Summary")
    pdf.setFont(fontfamily,normalsize)
    pdf.drawString(leftmargin, height - 120, "Collection")
    pdf.drawString(leftmargin + 150, height - 120, collection_info.get('name'))
    pdf.drawString(leftmargin, height - (120 + 2*lineheight*normalsize), "Status")
    pdf.drawString(leftmargin + 150, height - (120 + 2*lineheight*normalsize), compliance_status)
    pdf.setFont(fontitalic,normalsize)
    pdf.drawString(leftmargin + 150, height - (120 + 3*lineheight*normalsize), compliance_status_description)
    pdf.setFont(fontfamily,normalsize)
    pdf.drawString(leftmargin, height - (120 + 4*lineheight*normalsize), "Description")
    pdf.drawString(leftmargin + 150, height - (120 + 4*lineheight*normalsize), collection_description)
    pdf.drawString(leftmargin, height - (120 + 5*lineheight*normalsize), "Assets")
    pdf.drawString(leftmargin + 150, height - (120 + 5*lineheight*normalsize), str(len(assets)))

    pdf.setFont(fontbold, h2size)
    pdf.drawString(leftmargin, height - (120 + 8*lineheight*normalsize), 'Compliance Overview')
    pdf.setFont(fontfamily, normalsize)
    pdf.drawString(leftmargin, height - (120 + 10*lineheight*normalsize), 'Did Not Pass: {}'.format(compliance_overview['not_passing_policy']))
    pdf.drawString(leftmargin, height - (120 + 11*lineheight*normalsize), 'Passed: {}'.format(compliance_overview['passing_policy']))
    pdf.drawString(leftmargin, height - (120 + 12*lineheight*normalsize), 'Conditionally Pass: {}'.format(compliance_overview['conditionally_passing_policy']))
    pdf.drawString(leftmargin, height - (120 + 13*lineheight*normalsize), 'Not Assessed: {}'.format(compliance_overview['not_assessed']))

    pdf.setFont(fontbold, h2size)
    pdf.drawString(column2, height - (120 + 8*lineheight * normalsize), "Open Findings Impacting Policy")
    pdf.setFont(fontfamily, normalsize)
    pdf.drawString(column2, height - (120 + 10*lineheight * normalsize), "Very High Severity: {}".format(findingsbysev['sev5']))
    pdf.drawString(column2, height - (120 + 11*lineheight * normalsize), "High Severity: {}".format(findingsbysev['sev4']))
    pdf.drawString(column2, height - (120 + 12*lineheight * normalsize), "Medium Severity: {}".format(findingsbysev['sev3']))
    pdf.drawString(column2, height - (120 + 13*lineheight * normalsize), "Low Severity: {}".format(findingsbysev['sev2']))
    pdf.drawString(column2, height - (120 + 14*lineheight * normalsize), "Very Low Severity: {}".format(findingsbysev['sev1']))
    pdf.drawString(column2, height - (120 + 15*lineheight * normalsize), "Informational Severity: {}".format(findingsbysev['sev0']))

    write_footer(pdf, username, report_time,1)
    pdf.showPage()

def write_asset_section(pdf, compliance_type, icon, descriptiontext:list[str], section_start, assets):
    secondcolumn = leftmargin + 250
    thirdcolumn = leftmargin + 350
    fourthcolumn = leftmargin + 465
    iconspace = 15
    section_header = Collections().compliance_titles[compliance_type.upper()]

    pdf.drawImage(icon,leftmargin, section_start - 2, 13, 16) #drop the icon a little below the text line
    pdf.setFont(fontfamily,h2size)
    pdf.drawString(leftmargin + 20, section_start, section_header)

    lines = write_multiple_strings(pdf,leftmargin, section_start -(2*lineheight*normalsize), fontfamily, normalsize, descriptiontext)

    # list of assets with the policy compliance 
    pdf.setFont(fontbold, normalsize)
    pdf.drawString(leftmargin, section_start - (lines + 2)  *lineheight*normalsize, 'Asset')
    pdf.drawString(secondcolumn, section_start - (lines + 2) *lineheight*normalsize, 'Rules')
    pdf.drawString(thirdcolumn, section_start - (lines + 2) *lineheight*normalsize, 'Scan Requirements')
    pdf.drawString(fourthcolumn, section_start - (lines + 2) *lineheight*normalsize, 'Last Scan Date')
    pdf.setFont(fontfamily, normalsize)
    index = 0
    for asset in assets:
        if asset["attributes"]["policies"][0]["policy_compliance_status"] == compliance_type:
            status_rules = asset['attributes'].get('policy_passed_rules')
            status_scan = asset['attributes'].get('policy_passed_scan_requirements')                          
            status_grace = asset['attributes'].get('policy_in_grace_period')
            scan_date = asset['attributes'].get('last_completed_scan_date')
            if status_rules:
                rules_icon = os.path.join('resources', 'small','pass.png')
                rules_text = 'Passed'
            elif status_grace:
                rules_icon = os.path.join('resources','small', 'conditional.png')
                rules_text = 'Within Grace Period'
            else:
                rules_icon = os.path.join('resources','small','fail.png')
                rules_text = 'Did Not Pass'

            if status_scan:
                scan_icon = os.path.join('resources','small','pass.png')
                scan_text = 'Passed'
            else:
                scan_icon = os.path.join('resources','small','fail.png')
                scan_text = 'Did Not Pass'
                
            if scan_date:                
                date_unfiltered = scan_date
                datetimeobj = datetime.datetime.strptime(date_unfiltered, '%Y-%m-%dT%H:%M:%S.%f%z')
                date_text = datetime.datetime.strftime(datetimeobj, '%m-%d-%Y %H:%M') 
            else:
                date_text = 'Not Scanned'
                
            pdf.drawString(leftmargin, section_start - (lines + 3 +index) * lineheight * normalsize, asset['name'])
            pdf.drawImage(rules_icon, secondcolumn, section_start - (lines + 3 +index) * lineheight * normalsize, 8, 8)
            pdf.drawString(secondcolumn + iconspace, section_start - (lines + 3 +index) * lineheight * normalsize, rules_text)
            pdf.drawImage(scan_icon, thirdcolumn, section_start - (lines + 3 +index) * lineheight * normalsize, 8, 8)
            pdf.drawString(thirdcolumn + iconspace, section_start - (lines + 3 +index) * lineheight * normalsize, scan_text)
            pdf.drawString(fourthcolumn, section_start - (lines + 3 +index) * lineheight * normalsize, date_text)

            index += 1

def write_asset_policy(pdf, collection_info, username, report_time):
    didnotpassicon = os.path.join('resources','fail.png')
    conditionalicon = os.path.join('resources','conditional.png')
    passicon = os.path.join('resources','pass.png')
    notassessicon = os.path.join('resources','notassessed.png')
    assets = Collections().get_assets(collection_info.get('guid'))

    write_header(pdf,collection_info.get('name'))
    pdf.setFont(fontfamily,h1size)
    pdf.drawString(leftmargin, height - 120, 'Asset Policy Evaluation')

    not_passed = collection_info['compliance_overview']['not_passing_policy']
    conditional = collection_info['compliance_overview']['conditionally_passing_policy']
    passed = collection_info['compliance_overview']['passing_policy']
    not_assessed = collection_info['compliance_overview']['not_assessed']

    if not_passed > 0:
        # section - did not pass
        didnotpasstext = ['These assets have findings that violate policy rules and exceeded the remediation grace period or they have not been',
                            'scanned at the required frequency.']
        write_asset_section(pdf, 'DID_NOT_PASS', didnotpassicon, didnotpasstext, height - ( 120 + 3*lineheight*normalsize),assets)

    if conditional > 0:
        # section - conditional
        conditionaltext = ['These assets have findings that violate policy rules and are within the remediation grace period and they have been',
                            'scanned at the required frequency.']
        write_asset_section(pdf, 'CONDITIONAL_PASS', conditionalicon, conditionaltext, height - ( 120 + (not_passed+11)*lineheight*normalsize),assets)

    if passed > 0:
        # section - passed
        passedtext = ['These assets passed all the aspects of the policy, including rules and required scans.']
        write_asset_section(pdf, 'PASSED', passicon, passedtext, height - ( 120 + (not_passed + conditional + 19 )*lineheight*normalsize),assets)

    if not_assessed > 0:
        # section - not assessed
        notassessedtext = ['These assets have not been scanned.']
        write_asset_section(pdf, 'NOT_ASSESSED', notassessicon, notassessedtext, height - ( 120 + (not_passed + conditional + passed + 30) *lineheight*normalsize),assets)

    write_footer(pdf,username, report_time,2)
    pdf.showPage()

def write_report(collection_info):
    # cover page fields
    collection_name = collection_info.get('name')
    thisuser = get_self()
    username = thisuser.get('first_name') + ' ' + thisuser.get('last_name')
    report_time = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    report_name = "Veracode Collection - {}.pdf".format(collection_name)
    pdf = canvas.Canvas("Veracode Collection - {}.pdf".format(collection_name),pagesize=letter)

    write_cover_page(pdf,collection_name,username, report_time)

    write_summary(pdf, collection_info, username, report_time)

    write_asset_policy(pdf, collection_info,username, report_time)

    pdf.save()    

    return report_name

def main():
    parser = argparse.ArgumentParser(
        description='This script lists modules in which static findings were identified.')
    parser.add_argument('-c', '--collectionsid', help='Collections guid to create a report', required=False)
    parser.add_argument('-n', '--name', help='Collection name to generate a report for',required=False)
    args = parser.parse_args()

    if (args.name is not None):
       name = str(args.name)
       collections =  Collections().get_by_name(args.name)
       found = False
       for collection in collections:
           if (collection.get("name") == args.name):
              found = True
              collguid = collection.get("guid")
              status = "Guid for collection: {} is {}".format(args.name,collguid)
              print(status)
              log.info(status)
       if (not found):
          status = "Collection: {} does not exist".format(args.name)
          print(status)
          log.info(status)
          exit(1)
    elif (args.collectionsid is not None):
       collguid = args.collectionsid
    else:
       status = "Either a collection name or guid is required."
       print(status)
       log.info(status)
       exit(1)

    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    status = "Getting asset data for collection {}...".format(collguid)
    log.info(status)
    print(status)
    this_collection = get_collection(collguid)
    
    report_name = write_report(this_collection)

    status = "Created report at {}".format(report_name)
    print(status)
    log.info(status)
    
if __name__ == '__main__':
    main()