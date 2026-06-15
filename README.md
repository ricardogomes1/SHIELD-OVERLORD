




# 🛡️ Shield Platform // Overlord Industrial SOC

[![Security Core](https://img.shields.io/badge/Security-EDR%20%2F%20NDR-red?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202019-blue?style=for-the-badge)]()
[![Engine](https://img.shields.io/badge/Engine-PowerShell%205.1-yellow?style=for-the-badge)]()

A **Shield Platform** é um ecossistema tático e ultra-leve de **EDR (Endpoint Detection and Response)** e **NDR (Network Detection and Response)** desenvolvido sob medida para mitigar riscos corporativos em ambientes de alta densidade, como o **Windows Server 2019 RDS (Terminal Services)**. 

Operando através de uma arquitetura assíncrona de microsserviços nativos e uma interface distribuída em *Dark Mode*, o Shield monitora vetores de ataque, volumetria de tráfego de rede isolada por sessão e conformidade de Kernel com **zero impacto de performance (zero overhead)**.

---

## 🏗️ Arquitetura do Perímetro

O ecossistema é dividido em quatro componentes modulares que operam em harmonia:

* **`start_shield.bat` (Inicializador Mestre)**
    * Centraliza e repassa o token de privilégio administrativo (UAC) para todos os microsserviços em segundo plano com apenas 1 clique, eliminando pop-ups redundantes.
* **`ShieldCollector.ps1` (Engine Core & EDR)**
    * Realiza o tracking em tempo real de sessões RDP ativas/ociosas, consumo granular de RAM/Handles por utilizador e auditoria instantânea de ferramentas do sistema (`cmd.exe`, `powershell.exe`). Compila a *Timeline Forense* ordenada estritamente por ticks do processador.
* **`ShieldNetCollector.ps1` (Network Companion & NDR)**
    * Realiza o bypass de restrições Win32 de segurança cruzada do RDS usando telemetria CIM de Kernel. Mapeia sockets em escuta (`LISTENING`) e calcula a volumetria dinâmica real de transferência IP por processo (`io` em KB/MB), sendo totalmente imune a formatos longos de IPv6.
* **`ShieldApi.ps1` (Gateway Distribuído)**
    * Servidor HTTP assíncrono de alta performance construído diretamente sobre o driver de Kernel `HTTP.sys`. Unifica os payloads através de **costura atômica de strings em UTF-8 puro**, eliminando os gargalos de profundidade de objetos e estouros de memória do PowerShell 5.1.

---

## 🚀 Funcionalidades Principais

* **Painel RDS & Heatmap Explicável:** Grade visual intuitiva que categoriza os utilizadores por criticidade de risco, tempo ocioso e estouros de recursos.
* **RDP Shadow Unattended (`/noconsentprompt`):** Interceptação e controle remoto imediato por parte do Administrador para auditoria forense rápida, ignorando o pop-up de consentimento na máquina do utilizador.
* **Reset Atômico de Clipboard:** Expurgo e reinicialização forçada do processo órfão `rdpclip.exe`, isolado estritamente pelo ID da sessão RDP afetada, destravando a área de transferência instantaneamente.
* **Matriz de Hardening com 10 Sensores:** Checklist de conformidade hiper-sensível com roteamento automático de cores diretamente no front-end:
    * 🔵 **Informativo:** Firewall Ativo, NLA Obrigatório, SMBv1 Seguro, Registro Remoto Protegido, Ctrl+Alt+Del Exigido.
    * 🟢 **Baixo:** BitLocker Ativo, Assinaturas do Defender em dia, Windows Update Executando.
    * 🟡 **Médio:** Alertas de ausência de Assinatura Digital no SMB.
    * 🔴 **Alto / Crítico:** RealTime Protection do Antivírus Desativado ou Perfis de Firewall Inativos.
* **Rastreamento Ativo de Analistas:** Auditoria interna em tempo real que exibe os IPs dos analistas que estão a consultar a ferramenta diretamente na barra de título do console do PowerShell.
* 
<img width="1917" height="919" alt="Captura de tela 2026-06-15 133745" src="https://github.com/user-attachments/assets/881470ad-1e62-49e3-b2d3-8565c7f5dce9" />
<img width="1919" height="910" alt="Captura de tela 2026-06-15 133810" src="https://github.com/user-attachments/assets/8728eaa1-9a54-451d-901a-6d1d1143cab4" />
<img width="1919" height="918" alt="Captura de tela 2026-06-15 133822" src="https://github.com/user-attachments/assets/47a9bd1f-fd32-410e-8537-a7d3dd12c00c" />
<img width="1917" height="918" alt="Captura de tela 2026-06-15 133834" src="https://github.com/user-attachments/assets/2fe44383-356e-4c9f-90e6-1529d85fbc5b" />
<img width="1917" height="919" alt="Captura de tela 2026-06-15 133855" src="https://github.com/user-attachments/assets/faa647dc-3b56-4c60-84fa-2956a0791255" />
---

## ⚙️ Implantação e Inicialização

### 📂 Estrutura de Pastas Homologada
Para garantir o funcionamento correto dos caminhos estáticos da API, organize os arquivos na seguinte estrutura no servidor central:

```text
C:\Users\ricardo.gomes\Desktop\CYBER\SHIELD\ShieldPlatform\
├── start_shield.bat
├── ShieldCollector.ps1
├── ShieldNetCollector.ps1
├── ShieldApi.ps1
└── web\
    ├── index.html
    └── app.js
