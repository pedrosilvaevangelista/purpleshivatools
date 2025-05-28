# report.py
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from .recommendations import recommendations
import config as conf

def generate_metadata(tool_name="Purple Shiva Tools - █PING SWEEP Scanner"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0",
        "scan_type": "ping_sweep"
    }

def write_json_log(ip_range, total_hosts, active_hosts, duration, output_dir=None):
    """
    Gera relatório em formato JSON para ping sweep
    
    Args:
        ip_range (str): Range de IPs escaneado
        total_hosts (int): Total de hosts escaneados
        active_hosts (list): Lista de hosts ativos encontrados
        duration (float): Duração do scan em segundos
        output_dir (str): Diretório de saída (opcional)
    """
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pingsweep_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    # Processa informações dos hosts ativos
    active_hosts_info = []
    for host in active_hosts:
        host_info = {
            "ip": host['ip'],
            "status": host['status'],
            "response_time_ms": host.get('response_time'),
            "hostname": host.get('hostname', 'Unknown'),
            "discovered_at": datetime.now().isoformat()
        }
        active_hosts_info.append(host_info)

    # Estatísticas do scan
    success_rate = (len(active_hosts) / total_hosts * 100) if total_hosts > 0 else 0
    
    report_data = {
        "metadata": metadata,
        "scan_info": {
            "ip_range": ip_range,
            "total_hosts_scanned": total_hosts,
            "active_hosts_found": len(active_hosts),
            "success_rate_percent": round(success_rate, 2),
            "duration_seconds": round(duration, 2),
            "scan_completed_at": datetime.now().isoformat()
        },
        "active_hosts": active_hosts_info,
        "statistics": {
            "fastest_response_ms": min([h.get('response_time', float('inf')) for h in active_hosts if h.get('response_time')], default=None),
            "slowest_response_ms": max([h.get('response_time', 0) for h in active_hosts if h.get('response_time')], default=None),
            "average_response_ms": round(sum([h.get('response_time', 0) for h in active_hosts if h.get('response_time')]) / len([h for h in active_hosts if h.get('response_time')]), 2) if any(h.get('response_time') for h in active_hosts) else None,
            "hosts_with_hostname": len([h for h in active_hosts if h.get('hostname') and h.get('hostname') != 'Unknown']),
            "scan_rate_hosts_per_second": round(total_hosts / duration, 2) if duration > 0 else 0
        },
        "security_recommendations": recommendations
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"\n{conf.GREEN}[✓] Relatório JSON salvo em: {filepath}{conf.RESET}")
        print(f"{conf.YELLOW}[i] Resumo: {len(active_hosts)} hosts ativos de {total_hosts} escaneados ({success_rate:.2f}%){conf.RESET}")
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Falha ao salvar relatório JSON: {e}{conf.RESET}")
        raise

def write_xml_log(ip_range, total_hosts, active_hosts, duration, output_dir=None):
    """
    Gera relatório em formato XML para ping sweep
    
    Args:
        ip_range (str): Range de IPs escaneado  
        total_hosts (int): Total de hosts escaneados
        active_hosts (list): Lista de hosts ativos encontrados
        duration (float): Duração do scan em segundos
        output_dir (str): Diretório de saída (opcional)
    """
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Erro criando diretório '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pingsweep_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("pingsweep_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # Scan Info
    scan_info = ET.SubElement(root, "scan_info")
    ET.SubElement(scan_info, "ip_range").text = ip_range
    ET.SubElement(scan_info, "total_hosts_scanned").text = str(total_hosts)
    ET.SubElement(scan_info, "active_hosts_found").text = str(len(active_hosts))
    
    success_rate = (len(active_hosts) / total_hosts * 100) if total_hosts > 0 else 0
    ET.SubElement(scan_info, "success_rate_percent").text = str(round(success_rate, 2))
    ET.SubElement(scan_info, "duration_seconds").text = str(round(duration, 2))
    ET.SubElement(scan_info, "scan_completed_at").text = datetime.now().isoformat()
    
    # Active hosts
    active_hosts_elem = ET.SubElement(root, "active_hosts")
    for host in active_hosts:
        host_elem = ET.SubElement(active_hosts_elem, "host")
        ET.SubElement(host_elem, "ip").text = host['ip']
        ET.SubElement(host_elem, "status").text = host['status']
        
        if host.get('response_time'):
            ET.SubElement(host_elem, "response_time_ms").text = str(host['response_time'])
        
        hostname = host.get('hostname', 'Unknown')
        ET.SubElement(host_elem, "hostname").text = hostname
        ET.SubElement(host_elem, "discovered_at").text = datetime.now().isoformat()

    # Statistics
    stats_elem = ET.SubElement(root, "statistics")
    response_times = [h.get('response_time') for h in active_hosts if h.get('response_time')]
    
    if response_times:
        ET.SubElement(stats_elem, "fastest_response_ms").text = str(min(response_times))
        ET.SubElement(stats_elem, "slowest_response_ms").text = str(max(response_times))
        ET.SubElement(stats_elem, "average_response_ms").text = str(round(sum(response_times) / len(response_times), 2))
    
    hosts_with_hostname = len([h for h in active_hosts if h.get('hostname') and h.get('hostname') != 'Unknown'])
    ET.SubElement(stats_elem, "hosts_with_hostname").text = str(hosts_with_hostname)
    
    scan_rate = round(total_hosts / duration, 2) if duration > 0 else 0
    ET.SubElement(stats_elem, "scan_rate_hosts_per_second").text = str(scan_rate)

    # Security recommendations
    recs_elem = ET.SubElement(root, "security_recommendations")
    for rec in recommendations:
        rec_elem = ET.SubElement(recs_elem, "recommendation")
        ET.SubElement(rec_elem, "id").text = str(rec.get("id", ""))
        ET.SubElement(rec_elem, "title").text = rec.get("title", "")
        ET.SubElement(rec_elem, "severity").text = rec.get("severity", "")
        ET.SubElement(rec_elem, "contexto").text = rec.get("contexto", "")
        ET.SubElement(rec_elem, "description").text = rec.get("description", "")
        
        details = ET.SubElement(rec_elem, "details")
        for k, v in rec.get("specificDetails", {}).items():
            if isinstance(v, list):
                list_elem = ET.SubElement(details, k)
                for item in v:
                    if isinstance(item, dict):
                        dict_elem = ET.SubElement(list_elem, "item")
                        for dk, dv in item.items():
                            if isinstance(dv, list):
                                sub_list = ET.SubElement(dict_elem, dk)
                                for sub_item in dv:
                                    ET.SubElement(sub_list, "item").text = str(sub_item)
                            else:
                                ET.SubElement(dict_elem, dk).text = str(dv)
                    else:
                        ET.SubElement(list_elem, "item").text = str(item)
            elif isinstance(v, dict):
                dict_elem = ET.SubElement(details, k)
                for dk, dv in v.items():
                    if isinstance(dv, list):
                        sub_list = ET.SubElement(dict_elem, dk)
                        for sub_item in dv:
                            ET.SubElement(sub_list, "item").text = str(sub_item)
                    else:
                        ET.SubElement(dict_elem, dk).text = str(dv)
            else:
                ET.SubElement(details, k).text = str(v)
        
        sources_elem = ET.SubElement(rec_elem, "sources")
        for source in rec.get("sources", []):
            ET.SubElement(sources_elem, "source").text = source

    # Formatação do XML
    def indent_xml(elem, level=0):
        i = "\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for child in elem:
                indent_xml(child, level + 1)
            if not child.tail or not child.tail.strip():
                child.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i

    indent_xml(root)
    tree = ET.ElementTree(root)
    
    try:
        with open(filepath, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)
        print(f"\n{conf.GREEN}[✓] Relatório XML salvo em: {filepath}{conf.RESET}")
        success_rate = (len(active_hosts) / total_hosts * 100) if total_hosts > 0 else 0
        print(f"{conf.YELLOW}[i] Resumo: {len(active_hosts)} hosts ativos de {total_hosts} escaneados ({success_rate:.2f}%){conf.RESET}")
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Falha ao salvar relatório XML: {e}{conf.RESET}")
        raise

def print_quick_summary(active_hosts, total_hosts, duration):
    """
    Imprime um resumo rápido dos resultados na tela
    
    Args:
        active_hosts (list): Lista de hosts ativos
        total_hosts (int): Total de hosts escaneados  
        duration (float): Duração do scan
    """
    print(f"\n{conf.PURPLE}{'='*50}{conf.RESET}")
    print(f"{conf.PURPLE}{conf.BOLD} RESUMO RÁPIDO {conf.RESET}")
    print(f"{conf.PURPLE}{'='*50}{conf.RESET}")
    
    success_rate = (len(active_hosts) / total_hosts * 100) if total_hosts > 0 else 0
    
    print(f"\n{conf.YELLOW}Total escaneado: {conf.RESET}{total_hosts} hosts")
    print(f"{conf.GREEN}Hosts ativos: {conf.RESET}{len(active_hosts)}")
    print(f"{conf.CYAN}Taxa de sucesso: {conf.RESET}{success_rate:.2f}%")
    print(f"{conf.YELLOW}Tempo total: {conf.RESET}{duration:.2f}s")
    
    if active_hosts:
        response_times = [h.get('response_time') for h in active_hosts if h.get('response_time')]
        if response_times:
            print(f"{conf.CYAN}Resposta mais rápida: {conf.RESET}{min(response_times):.2f}ms")
            print(f"{conf.CYAN}Resposta mais lenta: {conf.RESET}{max(response_times):.2f}ms")
    
    print(f"{conf.PURPLE}{'='*50}{conf.RESET}")