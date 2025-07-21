# report.py
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .recommendations import recommendations
import config as conf

def generate_metadata(tool_name="Purple Shiva Tools - ARP Spoof"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0"
    }

def write_json_log(target_ip, packets_captured, gateway_ip, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arpspoof_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    report_data = {
        "metadata": metadata,
        "arp_spoof_info": {
            "target_ip": target_ip,
            "gateway_ip": gateway_ip,
            "packets_captured": packets_captured,
            "attack_duration": round(duration, 2) if duration else "N/A"
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

def write_xml_log(target_ip, packets_captured, gateway_ip, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arpspoof_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("arpspoof_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # ARP Spoof Info
    spoof_info = ET.SubElement(root, "arp_spoof_info")
    ET.SubElement(spoof_info, "target_ip").text = target_ip
    ET.SubElement(spoof_info, "gateway_ip").text = gateway_ip
    ET.SubElement(spoof_info, "packets_captured").text = str(packets_captured)
    ET.SubElement(spoof_info, "attack_duration").text = str(round(duration, 2)) if duration else "N/A"

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

def generate_report(arpspoof_instance, duration=None):
    """Generate both JSON and XML reports for the ARP spoof session"""
    try:
        json_path = write_json_log(
            target_ip=arpspoof_instance.target_ip,
            packets_captured=arpspoof_instance.packets_captured,
            gateway_ip=arpspoof_instance.gateway_ip,
            duration=duration
        )
        
        xml_path = write_xml_log(
            target_ip=arpspoof_instance.target_ip,
            packets_captured=arpspoof_instance.packets_captured,
            gateway_ip=arpspoof_instance.gateway_ip,
            duration=duration
        )
        
        return json_path, xml_path
    except Exception as e:
        print(f"{conf.RED}[!] Falha ao gerar relatórios: {e}{conf.RESET}")
        return None, None