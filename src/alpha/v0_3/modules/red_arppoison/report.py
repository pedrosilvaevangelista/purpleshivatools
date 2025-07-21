# report.py (Corrigido para ARP Poison)
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .recommendations import recommendations
import config as conf

def generate_metadata(tool_name="Purple Shiva Tools - ARP Poisoner"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0"
    }

def write_json_log(target_ip, gateway_ip, packets_sent, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arp_poison_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    report_data = {
        "metadata": metadata,
        "attack_info": {
            "target_ip": target_ip,
            "gateway_ip": gateway_ip,
            "packets_sent": packets_sent,
            "duration_seconds": round(duration, 2),
            "attack_type": "ARP Poisoning",
            "status": "completed"
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

def write_xml_log(target_ip, gateway_ip, packets_sent, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arp_poison_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("arp_poison_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # Attack Info
    attack_info = ET.SubElement(root, "attack_info")
    ET.SubElement(attack_info, "target_ip").text = target_ip
    ET.SubElement(attack_info, "gateway_ip").text = gateway_ip
    ET.SubElement(attack_info, "packets_sent").text = str(packets_sent)
    ET.SubElement(attack_info, "duration_seconds").text = str(round(duration, 2))
    ET.SubElement(attack_info, "attack_type").text = "ARP Poisoning"
    ET.SubElement(attack_info, "status").text = "completed"

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