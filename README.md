# Veracode Collections Report

Produces a report summarizing the security state of a Collection in the Veracode Platform. Collections allow you to group multiple assets (including application profiles) together into a single report so that you can provide a view of the security of a business application that consists of multiple components, for instance an application composed of many microservices, or a web back end with multiple mobile application front ends.

**Note**: The Collections feature is available only to Veracode customers in the Collections Early Adopter program. As the Collections feature is not GA yet, the functionality of the feature will change over time. This script is provided for illustration purposes only.

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-collections-report

Install dependencies:

    cd veracode-collections-report
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python vccollections.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vccollections.py (arguments)

Arguments supported include:

* --collectionsid, -c:  Collections guid for which to create a report.
* --name, -n:           Collections name for which to create a report.

Note: one of the two arguments is required

The Collections Report produces two outputs: a PDF and a CSV file.
