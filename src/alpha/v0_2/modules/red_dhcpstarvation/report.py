# report.py
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .recommendations import recommendations
import config as conf

def generate_metadata(tool_name="Purple Shiva Tools - DHCP Starvation"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0"
    }

def write_json_log(interface, requests_sent, responses_received, allocated_ips, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dhcp_starvation_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    report_data = {
        "metadata": metadata,
        "attack_info": {
            "interface": interface,
            "requests_sent": requests_sent,
            "responses_received": responses_received,
            "allocated_ips": allocated_ips,
            "unique_ips_count": len(allocated_ips),
            "success_rate": (responses_received / requests_sent * 100) if requests_sent > 0 else 0,
            "duration_seconds": round(duration, 2),
            "packets_per_second": round(requests_sent / duration, 2) if duration > 0 else 0
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

def write_xml_log(interface, requests_sent, responses_received, allocated_ips, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dhcp_starvation_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("dhcp_starvation_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # Attack Info
    attack_info = ET.SubElement(root, "attack_info")
    ET.SubElement(attack_info, "interface").text = interface
    ET.SubElement(attack_info, "requests_sent").text = str(requests_sent)
    ET.SubElement(attack_info, "responses_received").text = str(responses_received)
    ET.SubElement(attack_info, "unique_ips_count").text = str(len(allocated_ips))
    ET.SubElement(attack_info, "success_rate").text = str(round((responses_received / requests_sent * 100) if requests_sent > 0 else 0, 2))
    ET.SubElement(attack_info, "duration_seconds").text = str(round(duration, 2))
    ET.SubElement(attack_info, "packets_per_second").text = str(round(requests_sent / duration, 2) if duration > 0 else 0)
    
    # Allocated IPs
    ips_elem = ET.SubElement(attack_info, "allocated_ips")
    for ip in allocated_ips:
        ET.SubElement(ips_elem, "ip").text = str(ip)

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