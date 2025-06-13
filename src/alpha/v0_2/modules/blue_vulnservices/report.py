# report.py
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .recommendations import recommendations
import config as conf

def generate_metadata(tool_name="Purple Shiva Tools - Vulnerability Scanner"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0",
        "scan_type": "nmap_vulners"
    }

def write_json_log(scan_result, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vulnscan_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    report_data = {
        "metadata": metadata,
        "scan_info": {
            "target": scan_result.get("target", ""),
            "ports_scanned": scan_result.get("ports_scanned", []),
            "scan_type": scan_result.get("scan_type", "tcp"),
            "timing": scan_result.get("timing", 3),
            "duration_seconds": round(scan_result.get("duration", 0), 2),
            "scan_date": scan_result.get("scan_date", datetime.now().isoformat())
        },
        "results": {
            "open_ports": scan_result.get("open_ports", []),
            "services": scan_result.get("services", []),
            "vulnerabilities": scan_result.get("vulnerabilities", []),
            "summary": {
                "total_ports": len(scan_result.get("open_ports", [])),
                "total_services": len(scan_result.get("services", [])),
                "total_vulnerabilities": len(scan_result.get("vulnerabilities", [])),
                "critical_vulns": len([v for v in scan_result.get("vulnerabilities", []) if v.get("severity", "").lower() == "critical"]),
                "high_vulns": len([v for v in scan_result.get("vulnerabilities", []) if v.get("severity", "").lower() == "high"])
            }
        },
        "security_recommendations": recommendations
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"\n{conf.GREEN}[✓] Relatório JSON salvo em: {filepath}{conf.RESET}")
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Falha ao salvar relatório JSON: {e}{conf.RESET}")
        raise

def write_xml_log(scan_result, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vulnscan_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("vulnerability_scan_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # Scan Info
    scan_info = ET.SubElement(root, "scan_info")
    ET.SubElement(scan_info, "target").text = scan_result.get("target", "")
    ET.SubElement(scan_info, "scan_type").text = scan_result.get("scan_type", "tcp")
    ET.SubElement(scan_info, "timing").text = str(scan_result.get("timing", 3))
    ET.SubElement(scan_info, "duration_seconds").text = str(round(scan_result.get("duration", 0), 2))
    ET.SubElement(scan_info, "scan_date").text = scan_result.get("scan_date", datetime.now().isoformat())
    
    # Ports scanned
    ports_elem = ET.SubElement(scan_info, "ports_scanned")
    for port in scan_result.get("ports_scanned", []):
        ET.SubElement(ports_elem, "port").text = str(port)

    # Results
    results_elem = ET.SubElement(root, "results")
    
    # Open ports
    open_ports_elem = ET.SubElement(results_elem, "open_ports")
    for port_info in scan_result.get("open_ports", []):
        port_elem = ET.SubElement(open_ports_elem, "port")
        ET.SubElement(port_elem, "number").text = str(port_info.get("port", ""))
        ET.SubElement(port_elem, "protocol").text = port_info.get("protocol", "")
        ET.SubElement(port_elem, "state").text = port_info.get("state", "")

    # Services
    services_elem = ET.SubElement(results_elem, "services")
    for service in scan_result.get("services", []):
        service_elem = ET.SubElement(services_elem, "service")
        ET.SubElement(service_elem, "port").text = str(service.get("port", ""))
        ET.SubElement(service_elem, "name").text = service.get("name", "")
        ET.SubElement(service_elem, "version").text = service.get("version", "")
        ET.SubElement(service_elem, "product").text = service.get("product", "")

    # Vulnerabilities
    vulns_elem = ET.SubElement(results_elem, "vulnerabilities")
    for vuln in scan_result.get("vulnerabilities", []):
        vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
        ET.SubElement(vuln_elem, "cve").text = vuln.get("cve", "")
        ET.SubElement(vuln_elem, "severity").text = vuln.get("severity", "")
        ET.SubElement(vuln_elem, "score").text = str(vuln.get("score", ""))
        ET.SubElement(vuln_elem, "description").text = vuln.get("description", "")
        ET.SubElement(vuln_elem, "port").text = str(vuln.get("port", ""))
        ET.SubElement(vuln_elem, "service").text = vuln.get("service", "")

    # Summary
    summary_elem = ET.SubElement(results_elem, "summary")
    summary_data = {
        "total_ports": len(scan_result.get("open_ports", [])),
        "total_services": len(scan_result.get("services", [])),
        "total_vulnerabilities": len(scan_result.get("vulnerabilities", [])),
        "critical_vulns": len([v for v in scan_result.get("vulnerabilities", []) if v.get("severity", "").lower() == "critical"]),
        "high_vulns": len([v for v in scan_result.get("vulnerabilities", []) if v.get("severity", "").lower() == "high"])
    }
    for key, value in summary_data.items():
        ET.SubElement(summary_elem, key).text = str(value)

    # Security recommendations
    recs_elem = ET.SubElement(root, "security_recommendations")
    for rec in recommendations:
        rec_elem = ET.SubElement(recs_elem, "recommendation")
        ET.SubElement(rec_elem, "id").text = str(rec.get("id", ""))
        ET.SubElement(rec_elem, "title").text = rec.get("title", "")
        ET.SubElement(rec_elem, "severity").text = rec.get("severity", "")
        ET.SubElement(rec_elem, "description").text = rec.get("description", "")
        
        details = ET.SubElement(rec_elem, "details")
        for k, v in rec.get("specificDetails", {}).items():
            if isinstance(v, list):
                list_elem = ET.SubElement(details, k)
                for item in v:
                    ET.SubElement(list_elem, "item").text = str(item)
            elif isinstance(v, dict):
                dict_elem = ET.SubElement(details, k)
                for sub_k, sub_v in v.items():
                    sub_elem = ET.SubElement(dict_elem, sub_k)
                    if isinstance(sub_v, list):
                        for item in sub_v:
                            ET.SubElement(sub_elem, "item").text = str(item)
                    else:
                        sub_elem.text = str(sub_v)
            else:
                ET.SubElement(details, k).text = str(v)
        
        sources_elem = ET.SubElement(rec_elem, "sources")
        for source in rec.get("sources", []):
            ET.SubElement(sources_elem, "source").text = source

    tree = ET.ElementTree(root)
    try:
        with open(filepath, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)
        print(f"\n{conf.GREEN}[✓] Relatório XML salvo em: {filepath}{conf.RESET}")
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Falha ao salvar relatório XML: {e}{conf.RESET}")
        raise