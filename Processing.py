import requests, json, os, zipfile, smtplib, sys
import xml.etree.ElementTree as ET
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText




def sendUpdates(device, entry):
    email_server = smtplib.SMTP('smtp.gmail.com', 587)
    email_server.ehlo()
    email_server.starttls()
    email_server.login("VulnAlertBluehack@gmail.com", "BlueHack")
    
    
    update_email = MIMEMultipart('alternative')
    update_email['Subject'] = "[" + device['device_type'] + ": "+ device['device_name'] + "] has a new vulnerability\n\n"
    update_email['From'] = "VulnAlertBluehack@gmail.com"
    update_email['To'] = "rlb118@pitt.edu"
    
    recipient = "rlb118@pitt.edu"
    
    message = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <html>
    <head>
    </head>
    
    <body>
    <p>
    <b>Device:</b>
    <blockquote>
    {deviceName}
    </blockquote>
    
    <b>Date Modified:</b>
    <blockquote>
    {dMod}
    </blockquote>
    
    <b>Summary:</b>
    <blockquote>
    {summary}
    </blockquote>
    
    <a href="{article}">Link to article:</a>
    
    
    
    </p>
    </body>
    
    """.format(deviceName=device['device_name'], dMod=entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}last-modified-datetime").text, summary=entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}summary").text, article=entry.find("{http://scap.nist.gov/schema/vulnerability/0.4}references").find("{http://scap.nist.gov/schema/vulnerability/0.4}reference").get('href'))
    
   
    formMessage = MIMEText(message, 'html')
    
    update_email.attach(formMessage)
    
    
    
    email_server.sendmail("VulnAlertBluehack@gmail.com", recipient, update_email.as_string())
    email_server.quit()



vulnerability_zip = requests.get("https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.xml.zip")
vulnerability_zip.raise_for_status()
v_zip = open('nvdcve-2.0-modified.xml.zip', 'wb')
for chunk in vulnerability_zip.iter_content(100000):
    v_zip.write(chunk)
v_zip.close()


unzipped_folder = zipfile.ZipFile('nvdcve-2.0-modified.xml.zip', 'r')
unzipped_folder.extractall()
unzipped_folder.close();
os.remove('nvdcve-2.0-modified.xml.zip')

devices = open("devicesList.json", 'r')
devicesList = json.loads(devices.read())

vuln_list = ET.fromstring(open("nvdcve-2.0-modified.xml", 'r').read())



for device in devicesList:
    for entry in vuln_list:
        for vuln in entry.iter("{http://scap.nist.gov/schema/vulnerability/0.4}product"):
            
            if device['device_name'] in vuln.text:
                print("Sending update" + str(entry.attrib))
                sendUpdates(device, entry)
                sys.exit(0)

devices.close()

