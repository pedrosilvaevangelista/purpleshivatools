import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .recommendations import recommendations
import config as conf

def GenerateMetadata(toolName="Purple Shiva Tools - SSH Brute Force"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": toolName
    }

def WriteJsonLog(ip, username, result, passwordFile, totalPasswords, totalAttempts, duration, outputDir="reports"):
    if not os.path.exists(outputDir):
        os.makedirs(outputDir)

    timestampFile = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sshbruteforce_{timestampFile}.json"
    filepath = os.path.join(outputDir, filename)

    metadata = GenerateMetadata()

    reportData = {
        "metadata": metadata,
        "attackInfo": {
            "targetIp": ip,
            "username": username,
            "credentialFound": result,
            "passwordFile": passwordFile,
            "totalPasswords": totalPasswords,
            "totalAttempts": totalAttempts,
            "durationSeconds": duration
        },
        "securityrecommendations": recommendations
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(reportData, f, indent=4)
        print(f"\n{conf.BOLD}JSON report saved to {filepath}{conf.RESET}")
    except Exception as e:
        print(f"{conf.BOLD}[!] Failed to save JSON report: {e}{conf.RESET}")

def WriteXmlLog(ip, username, result, passwordFile, totalPasswords, totalAttempts, duration, outputDir="reports"):
    if not os.path.exists(outputDir):
        os.makedirs(outputDir)

    timestampFile = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sshbruteforce_{timestampFile}.xml"
    filepath = os.path.join(outputDir, filename)

    root = ET.Element("SshBruteForceReport")

    # Metadata
    metadataDict = GenerateMetadata()
    metadataElem = ET.SubElement(root, "Metadata")
    for key, value in metadataDict.items():
        ET.SubElement(metadataElem, key.capitalize()).text = str(value)

    # AttackInfo
    attackInfo = ET.SubElement(root, "AttackInfo")
    ET.SubElement(attackInfo, "TargetIp").text = ip
    ET.SubElement(attackInfo, "Username").text = username
    ET.SubElement(attackInfo, "CredentialFound").text = result
    ET.SubElement(attackInfo, "PasswordFile").text = passwordFile
    ET.SubElement(attackInfo, "TotalPasswords").text = str(totalPasswords)
    ET.SubElement(attackInfo, "TotalAttempts").text = str(totalAttempts)
    ET.SubElement(attackInfo, "DurationSeconds").text = str(duration)

    # Securityrecommendations
    recsElem = ET.SubElement(root, "Securityrecommendations")
    for rec in recommendations:
        recElem = ET.SubElement(recsElem, "Recommendation")
        ET.SubElement(recElem, "Id").text = str(rec.get("id", ""))
        ET.SubElement(recElem, "Title").text = rec.get("title", "")
        ET.SubElement(recElem, "Severity").text = rec.get("severity", "")
        ET.SubElement(recElem, "Description").text = rec.get("description", "")
        remediation = ET.SubElement(recElem, "Remediation")
        for k, v in rec.get("specificDetails", {}).items():
            ET.SubElement(remediation, k.capitalize()).text = str(v)
        sourcesElem = ET.SubElement(recElem, "Sources")
        for source in rec.get("sources", []):
            ET.SubElement(sourcesElem, "Source").text = source

    # Write XML all in one line (no pretty print)
    tree = ET.ElementTree(root)
    try:
        with open(filepath, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)
        print(f"\n{conf.BOLD}XML report saved to {filepath}{conf.RESET}")
    except Exception as e:
        print(f"{conf.BOLD}[!] Failed to save XML report: {e}{conf.RESET}")
