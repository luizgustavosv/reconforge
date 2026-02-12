#!/usr/bin/env python3
"""
ReconForge - Ferramenta Profissional de Information Gathering para Pentesters
Autor: Profissional de Cibersegurança
Versão: 1.0.0
"""

import asyncio
import aiohttp
import argparse
import json
import yaml
import logging
import sys
import os
import socket
import ssl
import subprocess
import threading
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import ipaddress
import whois
import dns.resolver
import nmap
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from tqdm import tqdm
import plotly.graph_objects as go
import plotly.express as px
from jinja2 import Template
import pandas as pd
import hashlib
import re
import json
from fake_useragent import UserAgent
import aiofiles
from PIL import Image
import io
import base64
import time
import webbrowser

init(autoreset=True)

# Banner da ferramenta
BANNER = f"""
{Fore.RED}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Fore.CYAN}ReconForge v1.0.0
{Fore.YELLOW}[!] Apenas para uso autorizado em testes de penetração
{Style.RESET_ALL}
"""

class ReconForge:
    """Classe principal do ReconForge"""
    
    def __init__(self, target: str, output_dir: str, config: Dict = None):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or self._load_default_config()
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "passive": {},
            "active": {},
            "vulnerabilities": [],
            "screenshots": [],
            "technologies": [],
            "subdomains": [],
            "ports": [],
            "dns_records": {},
            "whois_info": {},
            "whois_raw": {},
            "whois_domain_section": {},
            "whois_contact_section": {},
            "ssl_info": {},
            "waf_info": {},
            "emails": [],
            "endpoints": []
        }
        
        # Setup logging
        self._setup_logging()
        
    def _load_default_config(self) -> Dict:
        """Carrega configuração padrão"""
        return {
            "threads": 10,
            "timeout": 30,
            "user_agent": "ReconForge/1.0.0",
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "wordlist": {
                "directories": "/usr/share/wordlists/dirb/common.txt",
                "subdomains": "/usr/share/wordlists/amass/subdomains-top1mil.txt"
            }
        }
    
    def _setup_logging(self):
        """Configura sistema de logging"""
        log_file = self.output_dir / f"reconforge_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def run_passive_recon(self):
        """Executa reconhecimento passivo."""
        self.logger.info(f"[*] Iniciando reconhecimento passivo para: {self.target}")

        tasks = [
            self._whois_lookup(),
            self._dns_enumeration(),
            self._subdomain_enumeration(),
            self._technology_fingerprint(),
            self._email_harvesting(),
            self._ssl_analysis()
        ]

        await asyncio.gather(*tasks)

        self.results["passive"] = {
            "whois_info": dict(self.results.get("whois_info", {})),
            "dns_records": dict(self.results.get("dns_records", {})),
            "subdomains": list(self.results.get("subdomains", [])),
            "technologies": list(self.results.get("technologies", [])),
            "emails": list(self.results.get("emails", [])),
            "ssl_info": dict(self.results.get("ssl_info", {})),
            "summary": {
                "subdomains_count": len(self.results.get("subdomains", [])),
                "emails_count": len(self.results.get("emails", [])),
                "technologies_count": len(self.results.get("technologies", []))
            }
        }

    async def _whois_lookup(self):
        """Consulta WHOIS/RDAP com normalização e retorno completo (evita truncamento)."""
        try:
            self.logger.info("[*] Executando WHOIS lookup...")

            raw_target = self.target.strip()
            parsed = urlparse(raw_target if "://" in raw_target else f"//{raw_target}")
            lookup_target = (parsed.hostname or raw_target.split("/")[0]).strip().lower()

            def _rdap_event_map(events: Any) -> Dict[str, str]:
                if not isinstance(events, list):
                    return {}
                out: Dict[str, str] = {}
                for e in events:
                    if not isinstance(e, dict):
                        continue
                    action = e.get("eventAction")
                    date = e.get("eventDate")
                    if action and date:
                        out[str(action).lower()] = str(date)
                return out

            def _rdap_extract_entity_value(entity: Dict[str, Any]) -> Dict[str, Any]:
                """Extrai NOME/EMAIL/PAIS do vCard RDAP (quando disponível)."""
                vcard = entity.get("vcardArray")
                name = None
                email = None
                country = None

                # vcardArray format: ["vcard", [ [prop, params, type, value], ... ]]
                if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if not (isinstance(prop, list) and len(prop) >= 4):
                            continue
                        key = str(prop[0]).lower()
                        value = prop[3]
                        if key == "fn" and value and not name:
                            name = str(value).strip()
                        if key == "email" and value and not email:
                            email = str(value).strip()
                        if key == "adr" and isinstance(value, list) and len(value) >= 7:
                            # ADR: ["", "", street, city, region, postal, country]
                            c = value[6]
                            if c and not country:
                                country = str(c).strip()

                return {
                    "name": name,
                    "email": email,
                    "country": country,
                }

            def _set_whois_sections_for_domain(domain_name: str, rdap: Optional[Dict[str, Any]] = None):
                """
                Prepara as duas secoes exigidas pelo relatorio:
                - DOMINIO: campos de dominio
                - CONTATO: campos do contato do titular
                """
                domain_section: Dict[str, Any] = {
                    "domain": domain_name,
                    "titular": None,
                    "documento": None,
                    "responsavel": None,
                    "pais": None,
                    "contato_titular": None,
                    "contato_tecnico": None,
                    "servidores_dns": [],
                    "registros_ds": [],
                    "data_criacao": None,
                    "data_alteracao": None,
                    "status": None,
                }

                contact_section: Dict[str, Any] = {
                    "contact_id": None,
                    "nome": None,
                    "email": None,
                    "pais": None,
                    "data_criacao": None,
                    "data_alteracao": None,
                }

                if isinstance(rdap, dict):
                    # Nameservers
                    ns_list: List[str] = []
                    for ns in (rdap.get("nameservers", []) or []):
                        if isinstance(ns, dict) and ns.get("ldhName"):
                            ns_list.append(str(ns.get("ldhName")))
                    domain_section["servidores_dns"] = sorted(set(ns_list))

                    # DS records
                    ds_data = ((rdap.get("secureDNS") or {}).get("dsData") or []) if isinstance(rdap.get("secureDNS"), dict) else []
                    ds_out: List[str] = []
                    if isinstance(ds_data, list):
                        for ds in ds_data:
                            if not isinstance(ds, dict):
                                continue
                            # Minimal human-readable DS representation
                            parts = []
                            for key in ("keyTag", "algorithm", "digestType", "digest"):
                                if ds.get(key) is not None:
                                    parts.append(f"{key}={ds.get(key)}")
                            if parts:
                                ds_out.append(", ".join(parts))
                    domain_section["registros_ds"] = ds_out

                    # Status
                    status = rdap.get("status")
                    if isinstance(status, list):
                        domain_section["status"] = ", ".join(str(s) for s in status)
                    elif status:
                        domain_section["status"] = str(status)

                    # Dates (RDAP events)
                    emap = _rdap_event_map(rdap.get("events"))
                    domain_section["data_criacao"] = emap.get("registration") or emap.get("registered")
                    domain_section["data_alteracao"] = emap.get("last changed") or emap.get("last update of rdap database")

                    # Entities: registrant (titular), administrative (responsavel), technical (contato tecnico)
                    entities = rdap.get("entities", []) or []
                    registrant_entity = None
                    admin_entity = None
                    tech_entity = None
                    if isinstance(entities, list):
                        for ent in entities:
                            if not isinstance(ent, dict):
                                continue
                            roles = ent.get("roles", []) or []
                            roles_l = [str(r).lower() for r in roles] if isinstance(roles, list) else []
                            if "registrant" in roles_l and not registrant_entity:
                                registrant_entity = ent
                            if ("administrative" in roles_l or "admin" in roles_l) and not admin_entity:
                                admin_entity = ent
                            if ("technical" in roles_l or "tech" in roles_l) and not tech_entity:
                                tech_entity = ent

                    if registrant_entity:
                        reg_handle = registrant_entity.get("handle")
                        reg_vals = _rdap_extract_entity_value(registrant_entity)
                        domain_section["titular"] = reg_vals.get("name")
                        domain_section["pais"] = reg_vals.get("country") or rdap.get("country")
                        domain_section["contato_titular"] = reg_handle or reg_vals.get("email")

                        contact_section["contact_id"] = reg_handle
                        contact_section["nome"] = reg_vals.get("name")
                        contact_section["email"] = reg_vals.get("email")
                        contact_section["pais"] = reg_vals.get("country") or rdap.get("country")

                        reg_emap = _rdap_event_map(registrant_entity.get("events"))
                        contact_section["data_criacao"] = reg_emap.get("registration") or reg_emap.get("registered")
                        contact_section["data_alteracao"] = reg_emap.get("last changed") or reg_emap.get("last update of rdap database")

                    if admin_entity:
                        admin_vals = _rdap_extract_entity_value(admin_entity)
                        domain_section["responsavel"] = admin_vals.get("name") or admin_entity.get("handle")

                    if tech_entity:
                        tech_vals = _rdap_extract_entity_value(tech_entity)
                        domain_section["contato_tecnico"] = tech_vals.get("email") or tech_entity.get("handle") or tech_vals.get("name")

                # Persist (remove empty values but keep lists)
                self.results["whois_domain_section"] = {
                    k: v for k, v in domain_section.items()
                    if v not in (None, "", {}) and not (isinstance(v, list) and len(v) == 0)
                }
                self.results["whois_contact_section"] = {
                    k: v for k, v in contact_section.items()
                    if v not in (None, "", {})
                }

            # IPs: prefer RDAP via ipwhois (quando disponível)
            try:
                ip_obj = ipaddress.ip_address(lookup_target)
                lookup_ip = str(ip_obj)
                try:
                    from ipwhois import IPWhois  # type: ignore

                    rdap = IPWhois(lookup_ip).lookup_rdap()
                    self.results["whois_raw"] = rdap
                    self.results["whois_info"] = {
                        "query_target": lookup_ip,
                        "type": "ip_rdap",
                        "asn": rdap.get("asn"),
                        "asn_registry": rdap.get("asn_registry"),
                        "asn_country_code": rdap.get("asn_country_code"),
                        "asn_description": rdap.get("asn_description"),
                        "network_name": (rdap.get("network") or {}).get("name"),
                        "network_handle": (rdap.get("network") or {}).get("handle"),
                        "network_cidr": (rdap.get("network") or {}).get("cidr"),
                        "network_country": (rdap.get("network") or {}).get("country"),
                        "network_start_address": (rdap.get("network") or {}).get("start_address"),
                        "network_end_address": (rdap.get("network") or {}).get("end_address"),
                    }
                    self.results["whois_info"] = {
                        k: v for k, v in self.results["whois_info"].items() if v not in (None, "", [], {})
                    }
                    # For IPs, we don't have the requested domain/contact sections.
                    self.results["whois_domain_section"] = {"domain": lookup_ip}
                    self.results["whois_contact_section"] = {}
                    self.logger.info(f"[+] RDAP (IP) concluído para {lookup_ip}")
                    return
                except Exception as exc:
                    # Fallback: tenta RDAP público (pode funcionar sem ipwhois)
                    try:
                        resp = requests.get(f"https://rdap.org/ip/{lookup_ip}", timeout=15)
                        if resp.status_code == 200:
                            rdap = resp.json()
                            self.results["whois_raw"] = rdap
                            self.results["whois_info"] = {
                                "query_target": lookup_ip,
                                "type": "ip_rdap_http",
                                "name": rdap.get("name"),
                                "handle": rdap.get("handle"),
                                "startAddress": rdap.get("startAddress"),
                                "endAddress": rdap.get("endAddress"),
                                "ipVersion": rdap.get("ipVersion"),
                                "country": rdap.get("country"),
                                "status": rdap.get("status"),
                            }
                            self.results["whois_info"] = {
                                k: v for k, v in self.results["whois_info"].items() if v not in (None, "", [], {})
                            }
                            self.results["whois_domain_section"] = {"domain": lookup_ip}
                            self.results["whois_contact_section"] = {}
                            self.logger.info(f"[+] RDAP (IP) via HTTP concluído para {lookup_ip}")
                            return
                    except Exception:
                        pass

                    self.results["whois_info"] = {
                        "query_target": lookup_ip,
                        "type": "ip",
                        "error": f"Falha RDAP IP: {exc}"
                    }
                    self.results["whois_raw"] = {"error": str(exc)}
                    self.results["whois_domain_section"] = {"domain": lookup_ip}
                    self.results["whois_contact_section"] = {}
                    self.logger.warning(f"[-] Falha ao consultar RDAP para IP {lookup_ip}: {exc}")
                    return
            except ValueError:
                # Não é IP, segue para domínio.
                pass

            # Domínios: prefer RDAP público (mais consistente que WHOIS texto)
            try:
                rdap_resp = requests.get(f"https://rdap.org/domain/{lookup_target}", timeout=15)
                if rdap_resp.status_code == 200:
                    rdap = rdap_resp.json()
                    self.results["whois_raw"] = rdap

                    events = rdap.get("events", []) or []
                    event_map = {e.get("eventAction"): e.get("eventDate") for e in events if isinstance(e, dict)}

                    nameservers = []
                    for ns in (rdap.get("nameservers", []) or []):
                        if isinstance(ns, dict) and ns.get("ldhName"):
                            nameservers.append(ns.get("ldhName"))

                    self.results["whois_info"] = {
                        "query_target": lookup_target,
                        "type": "domain_rdap",
                        "ldhName": rdap.get("ldhName"),
                        "handle": rdap.get("handle"),
                        "status": rdap.get("status"),
                        "registrar": None,  # geralmente vem via entities; mantemos no raw
                        "registration": event_map.get("registration"),
                        "last_changed": event_map.get("last changed"),
                        "expiration": event_map.get("expiration"),
                        "nameservers": nameservers,
                    }
                    self.results["whois_info"] = {
                        k: v for k, v in self.results["whois_info"].items() if v not in (None, "", [], {})
                    }
                    _set_whois_sections_for_domain(lookup_target, rdap=rdap)
                    self.logger.info(f"[+] RDAP (domínio) concluído para {lookup_target}")
                    return
            except Exception:
                # segue para fallback WHOIS python
                pass

            candidates = [lookup_target]
            if lookup_target.startswith("www."):
                candidates.append(lookup_target[4:])

            whois_result = None
            query_used = None
            for candidate in candidates:
                try:
                    whois_result = whois.whois(candidate)
                    query_used = candidate
                    if whois_result:
                        break
                except Exception:
                    continue

            if not whois_result:
                self.results["whois_info"] = {
                    "query_target": lookup_target,
                    "status": "WHOIS sem resposta"
                }
                self.results["whois_raw"] = {"status": "WHOIS sem resposta"}
                _set_whois_sections_for_domain(lookup_target, rdap=None)
                self.logger.warning(f"[-] WHOIS sem dados para {lookup_target}")
                return

            def _serialize(value: Any) -> Any:
                if value is None:
                    return None
                if isinstance(value, (list, tuple, set)):
                    return [str(item) for item in value if item is not None]
                return str(value)

            # Captura o objeto bruto para exibição completa no relatório (sem truncamento)
            try:
                self.results["whois_raw"] = dict(whois_result)
            except Exception:
                self.results["whois_raw"] = {"raw": str(whois_result)}

            whois_info = {
                "query_target": query_used,
                "registrar": _serialize(getattr(whois_result, "registrar", None)),
                "creation_date": _serialize(getattr(whois_result, "creation_date", None)),
                "expiration_date": _serialize(getattr(whois_result, "expiration_date", None)),
                "name_servers": _serialize(getattr(whois_result, "name_servers", None)),
                "org": _serialize(getattr(whois_result, "org", None)),
                "country": _serialize(getattr(whois_result, "country", None)),
                "emails": _serialize(getattr(whois_result, "emails", None)),
                "status": _serialize(getattr(whois_result, "status", None)),
                "dnssec": _serialize(getattr(whois_result, "dnssec", None)),
            }

            self.results["whois_info"] = {
                key: value for key, value in whois_info.items() if value not in (None, [], "")
            }

            # Best-effort para preencher as secoes exigidas a partir do wrapper python-whois.
            # Campos como DOCUMENTO/REGISTROS DS geralmente nao existem aqui.
            _set_whois_sections_for_domain(query_used or lookup_target, rdap=None)
            if not self.results["whois_domain_section"].get("titular"):
                self.results["whois_domain_section"]["titular"] = _serialize(
                    getattr(whois_result, "org", None)
                )
            if not self.results["whois_domain_section"].get("pais"):
                self.results["whois_domain_section"]["pais"] = _serialize(
                    getattr(whois_result, "country", None)
                )
            if not self.results["whois_domain_section"].get("servidores_dns"):
                ns = getattr(whois_result, "name_servers", None)
                if ns:
                    self.results["whois_domain_section"]["servidores_dns"] = _serialize(ns)

            # Contact section fallback from emails
            if not self.results["whois_contact_section"].get("email"):
                self.results["whois_contact_section"]["email"] = _serialize(
                    getattr(whois_result, "emails", None)
                )
            self.logger.info(f"[+] WHOIS concluído para {query_used}")
        except Exception as e:
            self.results["whois_info"] = {
                "query_target": self.target,
                "error": str(e)
            }
            self.results["whois_raw"] = {"error": str(e)}
            self.results["whois_domain_section"] = {"domain": self.target, "error": str(e)}
            self.results["whois_contact_section"] = {}
            self.logger.error(f"[-] Erro no WHOIS: {e}")

    async def _dns_enumeration(self):
        """Enumeração completa de DNS"""
        self.logger.info("[*] Executando enumeração DNS...")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record)
                self.results["dns_records"][record] = [str(r) for r in answers]
            except:
                self.results["dns_records"][record] = []
        
        self.logger.info(f"[+] DNS enumeration concluído")
    
    async def _subdomain_enumeration(self):
        """Enumeração de subdomínios via Certificate Transparency (crt.sh)."""
        self.logger.info("[*] Enumerando subdomínios...")

        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        subdomains = set(self.results.get("subdomains", []))

        try:
            timeout = aiohttp.ClientTimeout(total=self.config.get("timeout", 30))
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        self.logger.warning(
                            f"[-] crt.sh retornou status {response.status} para {self.target}"
                        )
                        return

                    raw_text = await response.text()
                    if not raw_text.strip():
                        self.logger.warning("[-] Resposta vazia de crt.sh")
                        return

                    data = json.loads(raw_text)
                    for entry in data:
                        name_value = str(entry.get("name_value", "")).strip().lower()
                        if not name_value:
                            continue

                        # O campo name_value pode conter varios hosts separados por quebra de linha.
                        for candidate in name_value.splitlines():
                            normalized = candidate.strip().replace("*.", "")
                            if not normalized:
                                continue
                            if normalized == self.target or normalized.endswith(f".{self.target}"):
                                subdomains.add(normalized)

            self.results["subdomains"] = sorted(subdomains)
            self.logger.info(
                f"[+] Encontrados {len(self.results['subdomains'])} subdomínios via crt.sh"
            )

        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
            self.logger.error(f"[-] Erro na enumeração de subdomínios: {exc}")
        except Exception as exc:
            self.logger.error(f"[-] Erro inesperado na enumeração de subdomínios: {exc}")

    async def _technology_fingerprint(self):
        """Fingerprint de tecnologias"""
        self.logger.info("[*] Identificando tecnologias...")
        
        try:
            ua = UserAgent()
            headers = {'User-Agent': ua.random}
            
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(f"http://{self.target}", timeout=10) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Detecta tecnologias comuns
                    techs = []
                    
                    # Servidor Web
                    server = response.headers.get('Server', '')
                    if server:
                        techs.append(server)
                    
                    # Frameworks
                    if 'wp-content' in html or 'wordpress' in html.lower():
                        techs.append('WordPress')
                    if 'laravel' in html.lower():
                        techs.append('Laravel')
                    if 'django' in html.lower():
                        techs.append('Django')
                    if 'react' in html.lower():
                        techs.append('React')
                    if 'angular' in html.lower():
                        techs.append('Angular')
                    if 'vue' in html.lower():
                        techs.append('Vue.js')
                    
                    self.results["technologies"] = list(set(techs))
                    self.logger.info(f"[+] Tecnologias identificadas: {self.results['technologies']}")
        except Exception as e:
            self.logger.error(f"[-] Erro no fingerprint: {e}")
    
    async def _email_harvesting(self):
        """Coleta de emails"""
        self.logger.info("[*] Coletando emails...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{self.target}") as response:
                    html = await response.text()
                    
                    # Regex para emails
                    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    emails = re.findall(email_pattern, html)
                    
                    # Filtra emails do próprio domínio
                    target_domain = self.target.replace('www.', '')
                    target_emails = [e for e in emails if target_domain in e]
                    
                    self.results["emails"] = list(set(target_emails))
                    self.logger.info(f"[+] Encontrados {len(self.results['emails'])} emails")
        except Exception as e:
            self.logger.error(f"[-] Erro na coleta de emails: {e}")
    
    async def _ssl_analysis(self):
        """Análise SSL/TLS"""
        self.logger.info("[*] Analisando SSL/TLS...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results["ssl_info"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter'],
                        "san": cert.get('subjectAltName', []),
                        "version": cert.get('version', ''),
                        "serial_number": cert.get('serialNumber', '')
                    }
                    self.logger.info(f"[+] Análise SSL concluída")
        except Exception as e:
            self.logger.error(f"[-] Erro na análise SSL: {e}")
    
    async def run_active_recon(self, aggressive: bool = False):
        """Executa reconhecimento ativo."""
        self.logger.info(f"[*] Iniciando reconhecimento ativo para: {self.target}")

        tasks = [
            self._port_scanning(),
            self._waf_detection(),
            self._http_probing(),
            self._directory_bruteforce(),
            self._screenshot_capture()
        ]

        await asyncio.gather(*tasks)

        self.results["active"] = {
            "ports": list(self.results.get("ports", [])),
            "waf_info": self.results.get("waf_info", []),
            "endpoints": list(self.results.get("endpoints", [])),
            "screenshots": list(self.results.get("screenshots", [])),
            "vulnerabilities": list(self.results.get("vulnerabilities", [])),
            "summary": {
                "ports_count": len(self.results.get("ports", [])),
                "endpoints_count": len(self.results.get("endpoints", [])),
                "waf_detected": bool(self.results.get("waf_info"))
            }
        }

    async def _port_scanning(self):
        """Scan de portas com Nmap"""
        self.logger.info("[*] Iniciando scan de portas...")
        
        try:
            nmap_exe = shutil.which("nmap")
            if not nmap_exe and sys.platform.startswith("win"):
                win_candidates = [
                    r"C:\Program Files\Nmap\nmap.exe",
                    r"C:\Program Files (x86)\Nmap\nmap.exe",
                ]
                for candidate in win_candidates:
                    if Path(candidate).exists():
                        nmap_exe = candidate
                        break

            if not nmap_exe:
                self.logger.error(
                    "[-] Nmap não encontrado no sistema. No Windows, instale o Nmap e garanta nmap.exe no PATH "
                    "ou em C:\\Program Files\\Nmap\\nmap.exe. O scan de portas foi pulado."
                )
                return

            nm = nmap.PortScanner(nmap_search_path=[str(Path(nmap_exe).parent)])
            result = nm.scan(self.target, arguments='-sV -sC -O -T4 --top-ports 1000')
            
            if self.target in result['scan']:
                host_data = result['scan'][self.target]
                for port, port_data in host_data.get('tcp', {}).items():
                    service_info = {
                        "port": port,
                        "state": port_data.get('state', ''),
                        "service": port_data.get('name', ''),
                        "version": port_data.get('version', ''),
                        "product": port_data.get('product', '')
                    }
                    self.results["ports"].append(service_info)
                
                self.logger.info(f"[+] Port scanning concluído - {len(self.results['ports'])} portas abertas")
        except Exception as e:
            self.logger.error(f"[-] Erro no port scanning: {e}")
    
    async def _waf_detection(self):
        """Detecção de WAF"""
        self.logger.info("[*] Detectando WAF...")
        
        try:
            # Payloads para testar WAF
            payloads = [
                "' OR '1'='1",
                "<script>alert('xss')</script>",
                "../../../etc/passwd",
                "UNION SELECT NULL--"
            ]
            
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    async with session.get(f"http://{self.target}?id={payload}") as response:
                        headers = response.headers
                        
                        # Sinais comuns de WAF
                        waf_headers = ['x-sucuri-id', 'x-sucuri-cache', 'x-powered-by-plesk', 'x-waf']
                        detected_waf = []
                        
                        for header in waf_headers:
                            if header in headers:
                                detected_waf.append(header)
                        
                        if 'cloudflare' in str(headers).lower():
                            detected_waf.append('Cloudflare')
                        if 'akamai' in str(headers).lower():
                            detected_waf.append('Akamai')
                        if 'incapsula' in str(headers).lower():
                            detected_waf.append('Incapsula')
                        
                        self.results["waf_info"] = list(set(detected_waf))
                        
            self.logger.info(f"[+] WAF detectado: {self.results['waf_info']}")
        except Exception as e:
            self.logger.error(f"[-] Erro na detecção de WAF: {e}")
    
    async def _http_probing(self):
        """HTTP/HTTPS probing"""
        self.logger.info("[*] Realizando HTTP probing...")
        
        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{self.target}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, allow_redirects=True) as response:
                        endpoint_info = {
                            "url": str(response.url),
                            "status": response.status,
                            "protocol": protocol,
                            "server": response.headers.get('Server', ''),
                            "content_type": response.headers.get('Content-Type', ''),
                            "title": await self._get_page_title(response),
                            "headers": dict(response.headers)
                        }
                        self.results["endpoints"].append(endpoint_info)
                        self.logger.info(f"[+] {protocol.upper()} endpoint ativo: {response.status}")
            except:
                self.logger.debug(f"[-] {protocol.upper()} endpoint não responde")
    
    async def _get_page_title(self, response) -> str:
        """Extrai título da página"""
        try:
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.text.strip() if title else ''
        except:
            return ''
    
    async def _directory_bruteforce(self):
        """Bruteforce de diretórios"""
        self.logger.info("[*] Iniciando bruteforce de diretórios...")
        
        # Wordlist básica
        directories = [
            'admin', 'administrator', 'wp-admin', 'phpmyadmin', 
            'backup', 'uploads', 'images', 'css', 'js', 'api',
            'v1', 'v2', 'test', 'dev', 'development', 'staging'
        ]
        
        found_dirs = []
        
        async with aiohttp.ClientSession() as session:
            for directory in directories:
                try:
                    url = f"http://{self.target}/{directory}/"
                    async with session.get(url, timeout=5) as response:
                        if response.status not in [404, 403]:
                            found_dirs.append({
                                "directory": directory,
                                "url": url,
                                "status": response.status
                            })
                            self.logger.debug(f"[+] Diretório encontrado: {url} - {response.status}")
                except:
                    continue
        
        if found_dirs:
            self.results["endpoints"].extend(found_dirs)
            self.logger.info(f"[+] Encontrados {len(found_dirs)} diretórios")
    
    async def _screenshot_capture(self):
        """Captura de screenshot (simulada com placeholders)"""
        self.logger.info("[*] Capturando screenshot...")
        
        # Nota: Em produção, integrar com selenium/playwright
        # Esta é uma versão simplificada que gera um placeholder
        try:
            screenshot_data = {
                "timestamp": datetime.now().isoformat(),
                "url": f"http://{self.target}",
                "file": f"screenshot_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            }
            self.results["screenshots"].append(screenshot_data)
            self.logger.info(f"[+] Screenshot capturado: {screenshot_data['file']}")
        except Exception as e:
            self.logger.error(f"[-] Erro na captura de screenshot: {e}")
    
    def generate_report(self, format: str = 'html') -> Path:
        """Gera relatório completo e abre automaticamente o arquivo gerado."""
        self.logger.info(f"[*] Gerando relatório em formato {format}...")

        if format == 'html':
            report_file = self._generate_html_report()
        elif format == 'json':
            report_file = self._generate_json_report()
        elif format == 'pdf':
            report_file = self._generate_pdf_report()
        else:
            raise ValueError(f"Formato de relatório não suportado: {format}")

        self.logger.info(f"[+] Relatório gerado em: {report_file}")
        self._open_report_file(report_file)
        return report_file

    def _open_report_file(self, report_file: Path):
        """Abre o relatório gerado no aplicativo padrão do sistema."""
        try:
            full_path = report_file.resolve()
            if sys.platform.startswith("win"):
                os.startfile(str(full_path))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(full_path)], check=False)
            else:
                subprocess.run(["xdg-open", str(full_path)], check=False)
        except Exception as exc:
            self.logger.warning(f"[-] Falha ao abrir relatório automaticamente: {exc}")
            try:
                webbrowser.open_new_tab(report_file.resolve().as_uri())
            except Exception:
                pass

    def _generate_html_report(self):
        """Gera relatório HTML completo com o máximo de detalhes coletados."""

        # Normaliza e enriquece dados para o template sem perder o conteúdo bruto.
        subdomains = sorted(set(self.results.get("subdomains", [])))
        technologies = sorted(set(self.results.get("technologies", [])))
        emails = sorted(set(self.results.get("emails", [])))

        raw_waf = self.results.get("waf_info", [])
        if isinstance(raw_waf, dict):
            waf_info = [f"{key}: {value}" for key, value in raw_waf.items()]
        elif isinstance(raw_waf, list):
            waf_info = sorted(set(raw_waf))
        elif raw_waf:
            waf_info = [str(raw_waf)]
        else:
            waf_info = []

        processed_ports = []
        for port in self.results.get("ports", []):
            port_data = dict(port)
            try:
                port_num = int(port_data.get("port", 0))
            except (TypeError, ValueError):
                port_num = 0

            if port_num in (21, 23, 3389, 445):
                risk_label = "Alto"
                risk_class = "risk-high"
            elif port_num in (80, 443):
                risk_label = "Baixo"
                risk_class = "risk-low"
            else:
                risk_label = "Médio"
                risk_class = "risk-medium"

            port_data["port"] = port_num
            port_data["risk_label"] = risk_label
            port_data["risk_class"] = risk_class
            processed_ports.append(port_data)

        processed_endpoints = []
        admin_endpoints = []
        admin_markers = ("admin", "administrator", "wp-admin", "phpmyadmin", "manage", "dashboard", "panel")
        seen_urls = set()

        for endpoint in self.results.get("endpoints", []):
            endpoint_data = dict(endpoint)
            endpoint_url = str(endpoint_data.get("url", "")).strip()
            if endpoint_url in seen_urls:
                continue
            if endpoint_url:
                seen_urls.add(endpoint_url)

            headers = endpoint_data.get("headers", {})
            endpoint_data["headers_json"] = (
                json.dumps(headers, indent=2, ensure_ascii=False, default=str) if headers else ""
            )
            endpoint_data["endpoint_type"] = "Diretório" if endpoint_data.get("directory") else "Serviço Web"
            endpoint_data["status"] = endpoint_data.get("status", "N/A")
            endpoint_data["server"] = endpoint_data.get("server", "")
            endpoint_data["title"] = endpoint_data.get("title", "")

            haystack = f"{endpoint_url} {endpoint_data.get('directory', '')}".lower()
            if endpoint_url and any(marker in haystack for marker in admin_markers):
                admin_endpoints.append(endpoint_url)

            processed_endpoints.append(endpoint_data)

        admin_endpoints = sorted(set(admin_endpoints))

        screenshots = []
        for shot in self.results.get("screenshots", []):
            shot_data = dict(shot)
            file_name = shot_data.get("file", "")
            file_path = self.output_dir / file_name if file_name else None
            shot_data["exists"] = bool(file_path and file_path.exists())
            shot_data["path"] = str(file_path) if file_path else ""
            screenshots.append(shot_data)

        dns_records = self.results.get("dns_records", {})
        whois_info = self.results.get("whois_info", {})
        ssl_info = self.results.get("ssl_info", {})
        vulnerabilities = self.results.get("vulnerabilities", [])
        passive_data = self.results.get("passive", {})
        active_data = self.results.get("active", {})

        chart_counts = {
            "HTTP (80)": sum(1 for p in processed_ports if p.get("port") == 80),
            "HTTPS (443)": sum(1 for p in processed_ports if p.get("port") == 443),
            "SSH (22)": sum(1 for p in processed_ports if p.get("port") == 22),
            "FTP (21)": sum(1 for p in processed_ports if p.get("port") == 21),
            "SMTP (25)": sum(1 for p in processed_ports if p.get("port") == 25),
        }
        chart_counts["Outras"] = max(0, len(processed_ports) - sum(chart_counts.values()))

        context = {
            "target": self.results.get("target", self.target),
            "timestamp": self.results.get("timestamp", datetime.now().isoformat()),
            "subdomains": subdomains,
            "technologies": technologies,
            "emails": emails,
            "waf_info": waf_info,
            "ports": processed_ports,
            "dns_records": dns_records,
            "whois_info": whois_info,
            "whois_raw_json": json.dumps(self.results.get("whois_raw", {}), indent=2, ensure_ascii=False, default=str),
            "whois_domain_section": self.results.get("whois_domain_section", {}),
            "whois_contact_section": self.results.get("whois_contact_section", {}),
            "ssl_info": ssl_info,
            "endpoints": processed_endpoints,
            "admin_endpoints": admin_endpoints,
            "screenshots": screenshots,
            "vulnerabilities": vulnerabilities,
            "passive_data": passive_data,
            "active_data": active_data,
            "passive_json": json.dumps(passive_data, indent=2, ensure_ascii=False, default=str),
            "active_json": json.dumps(active_data, indent=2, ensure_ascii=False, default=str),
            "raw_results_json": json.dumps(self.results, indent=2, ensure_ascii=False, default=str),
            "chart_labels": json.dumps(list(chart_counts.keys()), ensure_ascii=False),
            "chart_values": json.dumps(list(chart_counts.values())),
            "chart_counts": chart_counts,
        }

        # Template HTML
        html_template = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ReconForge - Relatório de Pentest</title>
            <style>
                :root {
                    --primary-color: #ff3333;
                    --secondary-color: #1a1a1a;
                    --text-color: #333;
                    --bg-color: #f5f5f5;
                    --card-bg: white;
                    --success: #28a745;
                    --warning: #ffc107;
                    --danger: #dc3545;
                }

                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: var(--bg-color);
                    color: var(--text-color);
                    line-height: 1.6;
                }

                .container {
                    max-width: 1500px;
                    margin: 0 auto;
                    padding: 20px;
                }

                .header {
                    background: var(--secondary-color);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                }

                .header h1 {
                    color: var(--primary-color);
                    font-size: 2.2em;
                }

                .stats-container {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }

                .stat-card {
                    background: var(--card-bg);
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    border-left: 5px solid var(--primary-color);
                }

                .stat-card h3 {
                    color: var(--secondary-color);
                    font-size: 1em;
                    margin-bottom: 10px;
                }

                .stat-number {
                    font-size: 2.2em;
                    font-weight: bold;
                    color: var(--primary-color);
                }

                .section {
                    background: var(--card-bg);
                    padding: 25px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }

                .section h2 {
                    color: var(--secondary-color);
                    border-bottom: 2px solid var(--primary-color);
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                }

                .table {
                    width: 100%;
                    border-collapse: collapse;
                    table-layout: fixed;
                }

                .table th {
                    background: var(--secondary-color);
                    color: white;
                    padding: 12px;
                    text-align: left;
                }

                .table td {
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                    word-wrap: break-word;
                }

                .table tr:hover {
                    background: #f9f9f9;
                }

                .badge {
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-size: 0.85em;
                    font-weight: bold;
                }

                .badge-success {
                    background: var(--success);
                    color: white;
                }

                .badge-warning {
                    background: var(--warning);
                    color: black;
                }

                .badge-danger {
                    background: var(--danger);
                    color: white;
                }

                .risk-high {
                    color: var(--danger);
                    font-weight: bold;
                }

                .risk-medium {
                    color: #a06b00;
                    font-weight: bold;
                }

                .risk-low {
                    color: var(--success);
                    font-weight: bold;
                }

                .chips {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 10px;
                }

                .chip {
                    background: #eee;
                    border: 1px solid #ccc;
                    border-radius: 14px;
                    padding: 6px 12px;
                    font-size: 0.9em;
                }

                .code-block {
                    background: #0f172a;
                    color: #e2e8f0;
                    padding: 14px;
                    border-radius: 8px;
                    overflow-x: auto;
                    white-space: pre-wrap;
                    font-family: Consolas, 'Courier New', monospace;
                    font-size: 0.9em;
                }

                .split {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                }

                @media (max-width: 900px) {
                    .split {
                        grid-template-columns: 1fr;
                    }
                }

                .footer {
                    text-align: center;
                    padding: 20px;
                    color: #666;
                    border-top: 1px solid #ddd;
                }
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>ReconForge - Relatório Completo de Information Gathering</h1>
                    <p>Target: {{ target }}</p>
                    <p>Data: {{ timestamp }}</p>
                </div>

                <div class="stats-container">
                    <div class="stat-card">
                        <h3>Portas Abertas</h3>
                        <div class="stat-number">{{ ports|length }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Subdomínios</h3>
                        <div class="stat-number">{{ subdomains|length }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Endpoints</h3>
                        <div class="stat-number">{{ endpoints|length }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Tecnologias</h3>
                        <div class="stat-number">{{ technologies|length }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Emails</h3>
                        <div class="stat-number">{{ emails|length }}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Vulnerabilidades</h3>
                        <div class="stat-number">{{ vulnerabilities|length }}</div>
                    </div>
                </div>

                <div class="section">
                    <h2>Resumo Executivo</h2>
                    <ul>
                        <li>WAF detectado: {{ waf_info|join(', ') if waf_info else 'Nenhum identificável com a coleta atual' }}</li>
                        <li>Painéis administrativos potenciais: {{ admin_endpoints|length }}</li>
                        <li>Hosts no escopo (subdomínios + alvo principal): {{ subdomains|length + 1 }}</li>
                    </ul>
                </div>

                <div class="section">
                    <h2>Distribuição de Portas</h2>
                    <canvas id="portsChart" height="120"></canvas>
                </div>

                <div class="section">
                    <h2>WHOIS</h2>

                    <h3>DOMINIO: {{ whois_domain_section.domain if whois_domain_section.domain else target }}</h3>
                    <table class="table">
                        <thead>
                            <tr><th>Campo</th><th>Valor</th></tr>
                        </thead>
                        <tbody>
                            <tr><td>TITULAR</td><td>{{ whois_domain_section.titular if whois_domain_section.titular else 'N/A' }}</td></tr>
                            <tr><td>DOCUMENTO</td><td>{{ whois_domain_section.documento if whois_domain_section.documento else 'N/A' }}</td></tr>
                            <tr><td>RESPONSAVEL</td><td>{{ whois_domain_section.responsavel if whois_domain_section.responsavel else 'N/A' }}</td></tr>
                            <tr><td>PAIS</td><td>{{ whois_domain_section.pais if whois_domain_section.pais else 'N/A' }}</td></tr>
                            <tr><td>CONTATO DO TITULAR</td><td>{{ whois_domain_section.contato_titular if whois_domain_section.contato_titular else 'N/A' }}</td></tr>
                            <tr><td>CONTATO TECNICO</td><td>{{ whois_domain_section.contato_tecnico if whois_domain_section.contato_tecnico else 'N/A' }}</td></tr>
                            <tr><td>SERVIDORES DNS</td><td>{{ whois_domain_section.servidores_dns|join(', ') if whois_domain_section.servidores_dns else 'N/A' }}</td></tr>
                            <tr><td>REGISTROS DS</td><td>{{ whois_domain_section.registros_ds|join(' | ') if whois_domain_section.registros_ds else 'N/A' }}</td></tr>
                            <tr><td>DATA DE CRIACAO</td><td>{{ whois_domain_section.data_criacao if whois_domain_section.data_criacao else 'N/A' }}</td></tr>
                            <tr><td>DATA DE ALTERACAO</td><td>{{ whois_domain_section.data_alteracao if whois_domain_section.data_alteracao else 'N/A' }}</td></tr>
                            <tr><td>STATUS</td><td>{{ whois_domain_section.status if whois_domain_section.status else 'N/A' }}</td></tr>
                        </tbody>
                    </table>

                    <h3>CONTATO: {{ whois_contact_section.contact_id if whois_contact_section.contact_id else 'N/A' }}</h3>
                    <table class="table">
                        <thead>
                            <tr><th>Campo</th><th>Valor</th></tr>
                        </thead>
                        <tbody>
                            <tr><td>NOME</td><td>{{ whois_contact_section.nome if whois_contact_section.nome else 'N/A' }}</td></tr>
                            <tr><td>EMAIL</td><td>{{ whois_contact_section.email if whois_contact_section.email else 'N/A' }}</td></tr>
                            <tr><td>PAIS</td><td>{{ whois_contact_section.pais if whois_contact_section.pais else 'N/A' }}</td></tr>
                            <tr><td>DATA DE CRIACAO</td><td>{{ whois_contact_section.data_criacao if whois_contact_section.data_criacao else 'N/A' }}</td></tr>
                            <tr><td>DATA DE ALTERACAO</td><td>{{ whois_contact_section.data_alteracao if whois_contact_section.data_alteracao else 'N/A' }}</td></tr>
                        </tbody>
                    </table>

                    <details style="margin-top: 12px;">
                        <summary>WHOIS/RDAP bruto</summary>
                        <pre class="code-block">{{ whois_raw_json }}</pre>
                    </details>
                </div>

                <div class="section">
                    <h2>DNS Records (detalhado)</h2>
                    {% if dns_records %}
                        {% for record, values in dns_records.items() %}
                            <h3>{{ record }}</h3>
                            {% if values %}
                            <ul>
                                {% for value in values %}
                                <li>{{ value }}</li>
                                {% endfor %}
                            </ul>
                            {% else %}
                            <p>Sem registros retornados para {{ record }}.</p>
                            {% endif %}
                        {% endfor %}
                    {% else %}
                    <p>Sem dados DNS disponíveis.</p>
                    {% endif %}
                </div>

                <div class="section">
                    <h2>Subdomínios Descobertos (lista completa)</h2>
                    {% if subdomains %}
                    <ul>
                        {% for subdomain in subdomains %}
                        <li>{{ subdomain }}</li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <p>Nenhum subdomínio identificado.</p>
                    {% endif %}
                </div>

                <div class="section">
                    <h2>WAF Identificado</h2>
                    {% if waf_info %}
                    <div class="chips">
                        {% for waf in waf_info %}
                        <span class="chip">{{ waf }}</span>
                        {% endfor %}
                    </div>
                    {% else %}
                    <p>Nenhum WAF identificado com os indicadores atuais.</p>
                    {% endif %}
                </div>

                <div class="section">
                    <h2>Portas e Serviços (detalhado)</h2>
                    {% if ports %}
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Porta</th>
                                <th>Estado</th>
                                <th>Serviço</th>
                                <th>Produto</th>
                                <th>Versão</th>
                                <th>Risco</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for port in ports %}
                            <tr>
                                <td>{{ port.port }}</td>
                                <td>{{ port.state }}</td>
                                <td>{{ port.service }}</td>
                                <td>{{ port.product }}</td>
                                <td>{{ port.version }}</td>
                                <td class="{{ port.risk_class }}">{{ port.risk_label }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <p>Nenhuma porta registrada.</p>
                    {% endif %}
                </div>

                <div class="section">
                    <h2>Endpoints e Diretórios Encontrados</h2>
                    {% if endpoints %}
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Tipo</th>
                                <th>URL</th>
                                <th>Status</th>
                                <th>Servidor</th>
                                <th>Título</th>
                                <th>Detalhes</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for endpoint in endpoints %}
                            <tr>
                                <td>{{ endpoint.endpoint_type }}</td>
                                <td>{% if endpoint.url %}<a href="{{ endpoint.url }}" target="_blank">{{ endpoint.url }}</a>{% else %}N/A{% endif %}</td>
                                <td>
                                    <span class="badge {% if endpoint.status == 200 %}badge-success{% elif endpoint.status == 403 %}badge-warning{% else %}badge-danger{% endif %}">
                                        {{ endpoint.status }}
                                    </span>
                                </td>
                                <td>{{ endpoint.server }}</td>
                                <td>{{ endpoint.title }}</td>
                                <td>
                                    {% if endpoint.directory %}<div><strong>Directory:</strong> {{ endpoint.directory }}</div>{% endif %}
                                    {% if endpoint.protocol %}<div><strong>Protocol:</strong> {{ endpoint.protocol }}</div>{% endif %}
                                    {% if endpoint.content_type %}<div><strong>Content-Type:</strong> {{ endpoint.content_type }}</div>{% endif %}
                                    {% if endpoint.headers_json %}
                                    <details>
                                        <summary>Headers</summary>
                                        <pre class="code-block">{{ endpoint.headers_json }}</pre>
                                    </details>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <p>Nenhum endpoint encontrado.</p>
                    {% endif %}
                </div>

                <div class="section">
                    <h2>Painéis Administrativos Potenciais</h2>
                    {% if admin_endpoints %}
                    <ul>
                        {% for url in admin_endpoints %}
                        <li><a href="{{ url }}" target="_blank">{{ url }}</a></li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <p>Nenhum painel administrativo potencial identificado.</p>
                    {% endif %}
                </div>

                <div class="split">
                    <div class="section">
                        <h2>Tecnologias Detectadas</h2>
                        {% if technologies %}
                        <div class="chips">
                            {% for tech in technologies %}
                            <span class="chip">{{ tech }}</span>
                            {% endfor %}
                        </div>
                        {% else %}
                        <p>Nenhuma tecnologia identificada.</p>
                        {% endif %}
                    </div>

                    <div class="section">
                        <h2>Emails Encontrados</h2>
                        {% if emails %}
                        <ul>
                            {% for email in emails %}
                            <li>{{ email }}</li>
                            {% endfor %}
                        </ul>
                        {% else %}
                        <p>Nenhum email encontrado.</p>
                        {% endif %}
                    </div>
                </div>

                <div class="section">
                    <h2>Informações SSL/TLS (detalhado)</h2>
                    {% if ssl_info %}
                    <table class="table">
                        <thead>
                            <tr><th>Campo</th><th>Valor</th></tr>
                        </thead>
                        <tbody>
                            {% for key, value in ssl_info.items() %}
                            <tr>
                                <td>{{ key }}</td>
                                <td>{{ value }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <p>SSL não configurado ou não acessível.</p>
                    {% endif %}
                </div>

                <div class="section">
                    <h2>Screenshots Coletados</h2>
                    {% if screenshots %}
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>URL</th>
                                <th>Arquivo</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for shot in screenshots %}
                            <tr>
                                <td>{{ shot.timestamp }}</td>
                                <td>{% if shot.url %}<a href="{{ shot.url }}" target="_blank">{{ shot.url }}</a>{% else %}N/A{% endif %}</td>
                                <td>{{ shot.file }}</td>
                                <td>{{ 'Disponível' if shot.exists else 'Placeholder / não encontrado em disco' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <p>Nenhum screenshot coletado.</p>
                    {% endif %}
                </div>

                <div class="section">
                    <h2>Vulnerabilidades Correlacionadas</h2>
                    {% if vulnerabilities %}
                    <pre class="code-block">{{ vulnerabilities }}</pre>
                    {% else %}
                    <p>Nenhuma vulnerabilidade adicionada ao resultado nesta execução.</p>
                    {% endif %}
                </div>

                <div class="split">
                    <div class="section">
                        <h2>OSINT Passivo (raw)</h2>
                        <pre class="code-block">{{ passive_json }}</pre>
                    </div>
                    <div class="section">
                        <h2>Reconhecimento Ativo (raw)</h2>
                        <pre class="code-block">{{ active_json }}</pre>
                    </div>
                </div>

                <div class="section">
                    <h2>Dump Completo de Resultados (JSON)</h2>
                    <pre class="code-block">{{ raw_results_json }}</pre>
                </div>

                <div class="footer">
                    <p>Gerado pelo ReconForge v1.0.0 em {{ timestamp }}</p>
                    <p style="color: #ff3333;">Este relatório contém informações sensíveis. Restrinja o compartilhamento.</p>
                </div>
            </div>

            <script>
                const labels = {{ chart_labels | safe }};
                const values = {{ chart_values | safe }};
                const chartEl = document.getElementById('portsChart');
                const fb = document.getElementById('portsChartFallback');
                if (typeof Chart === 'undefined') {
                    if (fb) { fb.style.display = 'block'; }
                }
                if (chartEl && typeof Chart !== 'undefined') {
                    new Chart(chartEl, {
                        type: 'doughnut',
                        data: {
                            labels: labels,
                            datasets: [{
                                data: values,
                                backgroundColor: ['#ff3333', '#33ff33', '#3333ff', '#ffff33', '#ff9933', '#999999']
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: true
                        }
                    });
                }
            </script>
        </body>
        </html>
        """

        template = Template(html_template)
        html_content = template.render(**context)

        report_file = self.output_dir / f"reconforge_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_file.write_text(html_content, encoding="utf-8")

        self.logger.info(f"[+] Relatório HTML salvo: {report_file}")
        return report_file

    def _generate_json_report(self):
        """Gera relatório em JSON"""
        report_file = self.output_dir / f"reconforge_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file.write_text(json.dumps(self.results, indent=4, default=str, ensure_ascii=False), encoding="utf-8")
        self.logger.info(f"[+] Relatório JSON salvo: {report_file}")
        return report_file
    
    def _generate_pdf_report(self):
        """Gera relatório em PDF (placeholder)"""
        self.logger.warning("[-] Geração de PDF não implementada. Use weasyprint ou wkhtmltopdf.")
        return self._generate_html_report()

async def main():
    """Função principal"""
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description='ReconForge - Ferramenta Profissional de Information Gathering para Pentesters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python reconforge.py --target exemplo.com --output ./reports
  python reconforge.py --target 192.168.1.1 --aggressive --format html
  python reconforge.py --target exemplo.com --passive-only --output ./passive_recon
  python reconforge.py --target exemplo.com --api-keys keys.json --slack-webhook https://hooks.slack.com/services/xxx
        """
    )
    
    parser.add_argument('--target', '-t', required=True, help='Alvo (domínio ou IP)')
    parser.add_argument('--output', '-o', default='./reconforge_output', help='Diretório de saída')
    parser.add_argument('--aggressive', action='store_true', help='Modo agressivo (mais threads/requisições)')
    parser.add_argument('--stealth', action='store_true', help='Modo stealth (evita detecção)')
    parser.add_argument('--passive-only', action='store_true', help='Apenas reconhecimento passivo')
    parser.add_argument('--active-only', action='store_true', help='Apenas reconhecimento ativo')
    parser.add_argument('--no-screenshot', action='store_true', help='Desativa screenshots')
    parser.add_argument('--api-keys', help='Arquivo com chaves de API (JSON)')
    parser.add_argument('--proxy', help='Proxy para requisições (ex: http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout para requisições')
    parser.add_argument('--threads', type=int, default=10, help='Número de threads')
    parser.add_argument('--format', choices=['html', 'json', 'pdf'], default='html', help='Formato do relatório')
    parser.add_argument('--slack-webhook', help='Webhook para notificações Slack')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verboso')
    parser.add_argument('--quiet', '-q', action='store_true', help='Modo silencioso')
    
    args = parser.parse_args()
    
    # Carrega configuração
    config = {
        "threads": args.threads,
        "timeout": args.timeout,
        "aggressive": args.aggressive,
        "stealth": args.stealth
    }
    
    # Carrega API keys se fornecidas
    if args.api_keys:
        with open(args.api_keys, 'r') as f:
            config['api_keys'] = json.load(f)
    
    # Inicializa a ferramenta
    recon = ReconForge(args.target, args.output, config)
    
    try:
        # Executa reconhecimento
        if not args.active_only:
            await recon.run_passive_recon()
        
        if not args.passive_only:
            await recon.run_active_recon(args.aggressive)
        
        # Gera relatório
        recon.generate_report(args.format)
        
        # Notificação Slack se configurada
        if args.slack_webhook:
            await send_slack_notification(args.slack_webhook, recon.results)
        
        print(f"\n{Fore.GREEN}[✓] Reconhecimento concluído com sucesso!")
        print(f"{Fore.CYAN}[*] Resultados salvos em: {args.output}{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operação interrompida pelo usuário{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[✗] Erro fatal: {e}{Style.RESET_ALL}")
        recon.logger.error(f"Erro fatal: {e}", exc_info=True)
        sys.exit(1)

async def send_slack_notification(webhook: str, results: Dict):
    """Envia notificação via Slack"""
    try:
        message = {
            "text": f"🔍 *ReconForge - Reconhecimento Concluído*\n"
                   f"*Alvo:* {results['target']}\n"
                   f"*Portas abertas:* {len(results['ports'])}\n"
                   f"*Subdomínios:* {len(results['subdomains'])}\n"
                   f"*Tecnologias:* {len(results['technologies'])}\n"
                   f"*Emails:* {len(results['emails'])}"
        }
        
        async with aiohttp.ClientSession() as session:
            await session.post(webhook, json=message)
    except:
        pass

if __name__ == "__main__":
    asyncio.run(main())






