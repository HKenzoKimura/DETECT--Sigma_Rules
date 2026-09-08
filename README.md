# 🔵 DETECT — Sigma Detection Rules

> **Type:** Detection Engineering — Sigma Rules  
> **Coverage:** 12 rules · 6 MITRE tactics · 5 log sources  
> **Origin:** Rules derived from offensive research across this portfolio — each rule closes the loop on a documented attack technique  
> **Tested against:** Windows Security Event Log · Sysmon · Web/Proxy logs · PrintService Admin

> ⚠️ *These rules are detection-only. They identify adversary behavior documented in companion repos. No rule executes, modifies, or interacts with any system.*

## `Developed by: HKK`

---

## `$ cat ./objective.txt`


```
Repo ofensivo documenta técnica
        │
        ▼
Detection Opportunities section descreve o comportamento observável
        │
        ▼
Sigma rule formaliza o comportamento em lógica de detecção portável
        │
        ▼
Backend converter traduz para a linguagem do SIEM alvo (Splunk/Sentinel/Securonix)
```

Cada regra referencia o repo onde a técnica foi documentada — o contexto ofensivo é o que torna a regra precisa: sabe-se exatamente o que o atacante faz, qual artefato deixa, e o que o falso positivo legítimo parece.

---

## `$ cat ./rules_index.md`

| Arquivo | Técnica | MITRE | Log Source | Nível |
|---------|---------|-------|------------|-------|
| [kerberoasting_tgs_rc4_harvesting.yml](rules/credential_access/kerberoasting_tgs_rc4_harvesting.yml) | Kerberoasting via RC4 TGS bulk request | T1558.003 | Windows Security (4769) | 🔴 High |
| [cached_domain_credentials_mimikatz.yml](rules/credential_access/cached_domain_credentials_mimikatz.yml) | Cached credentials dump (lsadump::cache) | T1003.005 | Process Creation / Security (4663) | 🔴 High |
| [printnightmare_spoolsv_child_process.yml](rules/execution/printnightmare_spoolsv_child_process.yml) | PrintNightmare — shell spawned by spoolsv.exe | T1068 / T1569.002 | Sysmon (EventID 1) | 🔴 Critical |
| [printnightmare_driver_install_event.yml](rules/privilege_escalation/printnightmare_driver_install_event.yml) | PrintNightmare — driver install via RpcAddPrinterDriverEx | T1068 | PrintService/Admin (316/808) | 🔴 High |
| [lnk_powershell_encoded_hidden.yml](rules/execution/lnk_powershell_encoded_hidden.yml) | LNK masquerading — hidden encoded PowerShell | T1204.002 / T1059.001 | Sysmon (EventID 1) | 🔴 High |
| [wscript_com_outbound_connection.yml](rules/execution/wscript_com_outbound_connection.yml) | VBScript COM download (MSXML2.XMLHTTP bypass) | T1559.001 / T1071.001 | Sysmon (EventID 3) | 🔴 High |
| [pythonw_chromedriver_spawn.yml](rules/defense_evasion/pythonw_chromedriver_spawn.yml) | WhatsApp Spreader — pythonw.exe → chromedriver | T1534 / T1036 | Sysmon (EventID 1) | 🔴 High |
| [sap_netweaver_cve_2025_31324_file_upload.yml](rules/initial_access/sap_netweaver_cve_2025_31324_file_upload.yml) | CVE-2025-31324 — SAP unauthenticated file upload | T1190 / T1505.003 | Web/Proxy logs | 🔴 Critical |
| [spnego_cve_2025_47981_auth_flood.yml](rules/initial_access/spnego_cve_2025_47981_auth_flood.yml) | CVE-2025-47981 — SPNEGO NEGOEX auth flood | T1190 | Windows Security (4625) | 🔴 High |
| [supply_chain_python_exec_on_import.yml](rules/initial_access/supply_chain_python_exec_on_import.yml) | Supply chain — Python package execution on import | T1195.001 | Sysmon (EventID 1) | 🟡 Medium |
| [smb_null_session_anonymous.yml](rules/discovery/smb_null_session_anonymous.yml) | SMB null session anonymous enumeration | T1135 / T1087 | Windows Security (4624) | 🟡 Medium |
| [autorun_registry_reenabled.yml](rules/defense_evasion/autorun_registry_reenabled.yml) | AutoRun re-enabled via registry (hardening rollback) | T1091 | Sysmon (EventID 13) | 🟡 Medium |

---

## `$ cat ./mitre_coverage.yml`

```
credential_access:
  - T1558.003  # Kerberoasting → kerberoasting_tgs_rc4_harvesting.yml
  - T1003.005  # Cached Domain Credentials → cached_domain_credentials_mimikatz.yml

execution:
  - T1569.002  # Service Execution (PrintNightmare) → printnightmare_spoolsv_child_process.yml
  - T1059.001  # PowerShell Encoded → lnk_powershell_encoded_hidden.yml
  - T1059.005  # VBScript → wscript_com_outbound_connection.yml
  - T1204.002  # Malicious LNK → lnk_powershell_encoded_hidden.yml
  - T1559.001  # COM Objects → wscript_com_outbound_connection.yml

privilege_escalation:
  - T1068      # PrintNightmare LPE → printnightmare_driver_install_event.yml

initial_access:
  - T1190      # Exploit Public-Facing App → sap_netweaver_cve_2025_31324_file_upload.yml
  - T1190      # CVE-2025-47981 SPNEGO → spnego_cve_2025_47981_auth_flood.yml
  - T1195.001  # Supply Chain → supply_chain_python_exec_on_import.yml
  - T1505.003  # Web Shell → sap_netweaver_cve_2025_31324_file_upload.yml

defense_evasion:
  - T1036      # Masquerading → pythonw_chromedriver_spawn.yml
  - T1091      # AutoRun Bypass → autorun_registry_reenabled.yml

lateral_movement:
  - T1534      # Internal Spearphishing (WA Spreader) → pythonw_chromedriver_spawn.yml

discovery:
  - T1135      # Network Share Discovery → smb_null_session_anonymous.yml
  - T1087      # Account Discovery → smb_null_session_anonymous.yml
```

---

## `$ cat ./portfolio_crossref.md`

Cada regra é derivada da seção **Detection Opportunities** dos repositórios ofensivos:

| Regra | Repo de Origem | Seção |
|-------|---------------|-------|
| Kerberoasting RC4 | [TOOLS--Kerberoasting](/TOOLS--Kerberoasting) | `$ cat ./detection_opportunities.md` |
| Cached Credentials | [VULN--Unified_Mitigation_Suite](../VULN--Unified_Mitigation_Suite) | Mitigação ⑤ Cached Logon |
| PrintNightmare (child + driver) | [CVE-2021-1675](../CVE-2021-1675) | `$ cat ./detection_opportunities.md` |
| LNK Encoded PowerShell | [MALDEV--Suppy_Chain_Attack](../MALDEV--Suppy_Chain_Attack) | Design Decisions |
| VBScript COM download | [RE--WhatsApp_Spreader](../RE--WhatsApp_Spreader) | `$ cat ./detection_opportunities.md` |
| pythonw → chromedriver | [RE--WhatsApp_Spreader](../RE--WhatsApp_Spreader) | `$ cat ./detection_opportunities.md` |
| SAP NetWeaver upload | [CVE-2025-31324](../CVE-2025-31324) | `$ cat ./detection_opportunities.md` |
| SPNEGO auth flood | [CVE-2025-47981](../CVE-2025-47981) | `$ cat ./detection_opportunities.md` |
| Supply chain import | [MALDEV--Suppy_Chain_Attack](../MALDEV--Suppy_Chain_Attack) | `$ cat ./detection_opportunities.md` |
| SMB null session | [VULN--Unified_Mitigation_Suite](../VULN--Unified_Mitigation_Suite) | Mitigação ① Null Sessions |
| AutoRun re-enable | [VULN--Unified_Mitigation_Suite](../VULN--Unified_Mitigation_Suite) | Mitigação ⑧ AutoRun |

---

## `$ cat ./design_decisions.md`

### 1. Por que Sigma e não regras nativas de SIEM?

```
Splunk SPL:       index=wineventlog EventCode=4769 | ...
Sentinel KQL:     SecurityEvent | where EventID == 4769 | ...
Securonix:        eventid=4769 AND ...
Elastic EQL:      sequence by host.name [...]

vs.

Sigma YAML:       logsource: windows/security
                  detection:
                    selection:
                      EventID: 4769
```

Sigma é **agnóstico de plataforma** — uma regra compila para qualquer SIEM via `sigma-cli`. Em ambientes que migram de Splunk para Sentinel ou usam múltiplos SIEMs (ex: Securonix + CrowdStrike SIEM), manter regras nativas duplica o esforço e diverge ao longo do tempo.

### 2. Estrutura de detecção: selection + filter + condition

```yaml
detection:
  selection:          # o que PARECE o ataque
    EventID: 4769
    EncryptionType: '0x17'
  filter_legit:       # o que é DIFERENTE do ataque mas parece igual
    AccountName|endswith: '$'
  condition: selection and not filter_legit
```

**Por que separar filter em vez de negar direto na selection?**

Legibilidade e manutenção. Quando o rate de falso positivo aumentar (ex: um novo sistema começa a usar RC4 legitimamente), basta adicionar uma linha ao `filter_legit` — sem tocar na lógica de detection principal. Regras que misturam tudo em uma `selection` negada ficam ilegíveis em semanas.

### 3. Nível de evidência vs. nível de alerta

| Status | Significado | Usar quando |
|--------|-------------|-------------|
| `experimental` | Lógica não validada em produção | Técnica nova, sem baseline estabelecido |
| `test` | Validado logicamente, não em produção real | Regra revisada, aguarda tuning em lab |
| `stable` | Em produção, taxa de FP conhecida | Após tuning em ambiente real |

Todas as regras deste repo são `test` — derivadas de análise técnica, não de implantação em SIEM de produção.

### 4. `timeframe` + `count()` — threshold detection

```yaml
condition: selection | count(ServiceName) by AccountName > 5
timeframe: 5m
```

Nem toda instância de `EventID: 4769` é Kerberoasting — qualquer usuário gera um 4769 ao abrir um share de rede. O **threshold** é o que diferencia uso legítimo de harvesting. A escolha de `> 5 SPNs em 5 minutos` por conta é calibrada para detectar ferramentas automatizadas sem gerar alertas para usuários normais que abrem múltiplas shares.

Ajustar conforme o baseline do ambiente: ambientes com muitos usuários heavy (ex: devs com acesso a muitos serviços) podem precisar de `> 15` ou janela de `1m`.

### 5. `|contains|all` vs. `|contains`

```yaml
# AND implícito — AMBOS devem estar presentes na CommandLine
CommandLine|contains|all:
  - '-EncodedCommand'
  - '-WindowStyle'

# OR implícito — QUALQUER um é suficiente
CommandLine|contains:
  - '-enc'
  - '-EncodedCommand'
```

`|contains|all` evita falsos positivos quando um dos termos é comum isolado. `-WindowStyle` aparece em scripts legítimos; `-EncodedCommand` também. Juntos em um PowerShell de LNK são um sinal forte.

---

## `$ cat ./usage.sh`

```bash
# Instalar sigma-cli
pip install sigma-cli

# Instalar backend do SIEM alvo
sigma plugin install splunk
sigma plugin install microsoft365defender
sigma plugin install elasticsearch

# Converter uma regra para Splunk SPL
sigma convert -t splunk rules/credential_access/kerberoasting_tgs_rc4_harvesting.yml

# Converter todo o repo para Microsoft Sentinel KQL
sigma convert -t microsoft365defender rules/ -o sentinel_rules.kql

# Converter com pipeline (mapeamento de campos do seu SIEM)
sigma convert -t splunk -p sysmon rules/execution/

# Validar sintaxe de todas as regras
sigma check rules/

# Listar backends disponíveis
sigma plugin list
```

```bash
# Output esperado (Splunk):
index=wineventlog (EventCode=4769 TicketEncryptionType="0x17" Status="0x0")
  NOT (AccountName="*$")
  NOT (ServiceName="krbtgt*")
  NOT (IpAddress="::")
| stats dc(ServiceName) as spn_count by AccountName
| where spn_count > 5
```

```bash
# Output esperado (Microsoft Sentinel KQL):
SecurityEvent
| where EventID == 4769
    and TicketEncryptionType == "0x17"
    and Status == "0x0"
    and AccountName !endswith "$"
    and ServiceName !startswith "krbtgt"
    and IpAddress != "::1"
| summarize SPNCount = dcount(ServiceName) by AccountName, bin(TimeGenerated, 5m)
| where SPNCount > 5
```

---

## `$ cat ./structure.txt`

```
DETECT--Sigma_Rules/
├── README.md
└── rules/
    ├── credential_access/
    │   ├── kerberoasting_tgs_rc4_harvesting.yml          # T1558.003
    │   └── cached_domain_credentials_mimikatz.yml        # T1003.005
    ├── execution/
    │   ├── printnightmare_spoolsv_child_process.yml      # T1569.002 / T1068
    │   ├── lnk_powershell_encoded_hidden.yml             # T1204.002 / T1059.001
    │   └── wscript_com_outbound_connection.yml           # T1559.001
    ├── initial_access/
    │   ├── sap_netweaver_cve_2025_31324_file_upload.yml  # T1190 / T1505.003
    │   ├── spnego_cve_2025_47981_auth_flood.yml          # T1190
    │   └── supply_chain_python_exec_on_import.yml        # T1195.001
    ├── defense_evasion/
    │   ├── pythonw_chromedriver_spawn.yml                # T1534 / T1036
    │   └── autorun_registry_reenabled.yml                # T1091
    ├── privilege_escalation/
    │   └── printnightmare_driver_install_event.yml       # T1068
    └── discovery/
        └── smb_null_session_anonymous.yml                # T1135 / T1087
```

---

## `$ cat ./lessons_learned.txt`

```
[+] Ter o contexto ofensivo (como o ataque funciona) torna a regra muito mais precisa
[+] Separar selection de filter torna o tuning incremental sem reescrever a regra inteira
[+] Threshold detection (count > N em timeframe) é essencial para evitar FP em eventos comuns
[+] status: test / experimental / stable comunica maturidade da regra para o time
[+] Cross-referencing com repos ofensivos cria rastreabilidade: cada alerta remete ao playbook
[-] Regras sem validação em produção têm taxa de FP desconhecida — status: test é honesto
[-] Campos como TicketEncryptionType variam entre versões do Windows e configurações de audit
[-] Regras de threshold dependem do backend suportar timeframe + count — nem todos suportam
[-] supply_chain_python_exec_on_import.yml tem alto FP potencial — precisa de baseline antes de produção
[→] Próximos passos: adicionar regras para ASREPRoasting (T1558.004), DCSync (T1003.006),
    Pass-the-Ticket (T1550.003), e cobertura de Linux (auditd source)
```

---

*Sigma Detection Rules · Purple Team · MITRE ATT&CK Mapped · Multi-SIEM Compatible · Portfolio-Derived*
