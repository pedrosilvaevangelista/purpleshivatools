# report.py
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .recommendations import recommendations
import config as conf

def generate_metadata(tool_name="Purple Shiva Tools - ENUMERAÇÃO SMB"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0"
    }

def write_json_log(results, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"smbenum_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    report_data = {
        "metadata": metadata,
        "enumeration_results": results,
        "security_recommendations": recommendations,
        "summary": generate_summary(results)
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"\n{conf.GREEN}[✓] Relatório JSON salvo em: {filepath}{conf.RESET}")
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Falha ao salvar relatório JSON: {e}{conf.RESET}")
        raise

def write_xml_log(results, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"smbenum_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("smb_enumeration_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # Results
    results_elem = ET.SubElement(root, "enumeration_results")
    
    # Target info
    ET.SubElement(results_elem, "target_ip").text = results.get("target_ip", "")
    ET.SubElement(results_elem, "timestamp").text = results.get("timestamp", "")
    ET.SubElement(results_elem, "duration").text = str(results.get("duration", 0))

    # Open ports
    if results.get("open_ports"):
        ports_elem = ET.SubElement(results_elem, "open_ports")
        for port_info in results["open_ports"]:
            port_elem = ET.SubElement(ports_elem, "port")
            ET.SubElement(port_elem, "number").text = str(port_info["port"])
            ET.SubElement(port_elem, "service").text = port_info["service"]
            ET.SubElement(port_elem, "status").text = port_info["status"]

    # NetBIOS info
    if results.get("netbios_info"):
        netbios_elem = ET.SubElement(results_elem, "netbios_info")
        for name, info in results["netbios_info"].items():
            if isinstance(info, dict):
                name_elem = ET.SubElement(netbios_elem, "netbios_name")
                ET.SubElement(name_elem, "name").text = name
                ET.SubElement(name_elem, "code").text = info.get("code", "")
                ET.SubElement(name_elem, "type").text = info.get("type", "")
                ET.SubElement(name_elem, "status").text = info.get("status", "")

    # SMB shares
    if results.get("shares"):
        shares_elem = ET.SubElement(results_elem, "shares")
        for share in results["shares"]:
            share_elem = ET.SubElement(shares_elem, "share")
            ET.SubElement(share_elem, "name").text = share["name"]
            ET.SubElement(share_elem, "type").text = share["type"]
            ET.SubElement(share_elem, "comment").text = share["comment"]

    # SMB info
    if results.get("smb_info"):
        smb_elem = ET.SubElement(results_elem, "smb_info")
        for key, value in results["smb_info"].items():
            if isinstance(value, list):
                list_elem = ET.SubElement(smb_elem, key)
                for item in value:
                    ET.SubElement(list_elem, "item").text = str(item)
            else:
                ET.SubElement(smb_elem, key).text = str(value)

    # Security info
    if results.get("security_info"):
        security_elem = ET.SubElement(results_elem, "security_info")
        for key, value in results["security_info"].items():
            if isinstance(value, dict):
                sub_elem = ET.SubElement(security_elem, key)
                for sub_key, sub_value in value.items():
                    ET.SubElement(sub_elem, sub_key).text = str(sub_value)
            else:
                ET.SubElement(security_elem, key).text = str(value)

    # Errors
    if results.get("errors"):
        errors_elem = ET.SubElement(results_elem, "errors")
        for error in results["errors"]:
            ET.SubElement(errors_elem, "error").text = error

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
                    if isinstance(item, str):
                        ET.SubElement(list_elem, "item").text = item
                    else:
                        sub_item = ET.SubElement(list_elem, "item")
                        for sub_k, sub_v in item.items():
                            ET.SubElement(sub_item, sub_k).text = str(sub_v)
            elif isinstance(v, dict):
                dict_elem = ET.SubElement(details, k)
                for sub_k, sub_v in v.items():
                    if isinstance(sub_v, list):
                        sub_list = ET.SubElement(dict_elem, sub_k)
                        for sub_item in sub_v:
                            ET.SubElement(sub_list, "item").text = str(sub_item)
                    else:
                        ET.SubElement(dict_elem, sub_k).text = str(sub_v)
            else:
                ET.SubElement(details, k).text = str(v)
        
        sources_elem = ET.SubElement(rec_elem, "sources")
        for source in rec.get("sources", []):
            ET.SubElement(sources_elem, "source").text = source

    # Summary
    summary_elem = ET.SubElement(root, "summary")
    summary_data = generate_summary(results)
    for key, value in summary_data.items():
        if isinstance(value, list):
            list_elem = ET.SubElement(summary_elem, key)
            for item in value:
                ET.SubElement(list_elem, "item").text = str(item)
        else:
            ET.SubElement(summary_elem, key).text = str(value)

    tree = ET.ElementTree(root)
    try:
        with open(filepath, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)
        print(f"\n{conf.GREEN}[✓] Relatório XML salvo em: {filepath}{conf.RESET}")
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Falha ao salvar relatório XML: {e}{conf.RESET}")
        raise

def generate_summary(results):
    """Gera resumo dos resultados da enumeração"""
    summary = {
        "target_ip": results.get("target_ip", ""),
        "scan_duration": results.get("duration", 0),
        "open_ports_count": len(results.get("open_ports", [])),
        "shares_found": len(results.get("shares", [])),
        "netbios_names_found": len(results.get("netbios_info", {})),
        "users_found": len(results.get("users", [])),
        "sessions_found": len(results.get("sessions", [])),
        "errors_count": len(results.get("errors", [])),
        "vulnerabilities_detected": [],
        "security_status": "SECURE"
    }
    
    # Detectar vulnerabilidades baseadas nos resultados
    security_info = results.get("security_info", {})
    
    if security_info.get("null_session", {}).get("allowed"):
        summary["vulnerabilities_detected"].append("Sessões nulas permitidas")
        summary["security_status"] = "VULNERABLE"
        
    if not security_info.get("smb_signing", {}).get("required"):
        summary["vulnerabilities_detected"].append("Assinatura SMB não obrigatória")
        summary["security_status"] = "VULNERABLE"
        
    # Verificar versões SMB legadas
    smb_info = results.get("smb_info", {})
    if any("SMBv1" in str(v) or "1.0" in str(v) for v in smb_info.values()):
        summary["vulnerabilities_detected"].append("Protocolo SMBv1 detectado")
        summary["security_status"] = "VULNERABLE"
    
    # Verificar compartilhamentos administrativos expostos
    shares = results.get("shares", [])
    admin_shares = [share for share in shares if share.get("name", "").upper() in ["ADMIN$", "C$", "IPC$"]]
    if admin_shares:
        summary["admin_shares_exposed"] = len(admin_shares)
        if any(share.get("type", "") != "IPC" for share in admin_shares):
            summary["vulnerabilities_detected"].append("Compartilhamentos administrativos expostos")
            summary["security_status"] = "WARNING"
    
    # Verificar se há muitas portas abertas
    open_ports = results.get("open_ports", [])
    if len(open_ports) > 3:
        summary["vulnerabilities_detected"].append("Múltiplas portas SMB/NetBIOS abertas")
        
    # Status final de segurança
    if summary["vulnerabilities_detected"] and summary["security_status"] == "SECURE":
        summary["security_status"] = "WARNING"
    
    return summary