# Cybersecurity Playbook for SOC



 **Cybersecurity Playbook for SOC [US]** and **Manual de segurança cibernética para SOC[BR]**
 
 
 001. **Attack utilizing a know vulnerability** / **Ataque utilizando uma vulnerabilidade conhecida**

*Foi detectado um intruso que utiliza uma vulnerabilidade conhecida.

**Detecção**:
    
    • Detecção de rede a partir IDS/IPS/Capacidade de detecção de ameaça de rede
    • Detecção deponto de extremidade a partir do host de destino

**Verificação**:
    
    • O evento é validado com a lista de ativos, se o software/hardware vulneravel
    • Verificação precisará ser feita manualmente suporte do ativo de destino
    • O evento é correlacionado com o software de segurança de ponto final (EDR/XDR) confirmarse o ataque é bem-sucedido ou nao.

**Comunicação**:
    
    • Para ataques bem-sucedidos, inicie a triagem usando informações de criticidade de ataque e ativos
    • Realizar escalonamento de acordo com os resultados da triagem e plano de escalonamento predefinido.

**Ação**:
    
    • Para ataques bem-sucedidos, execute a contenção nos hosts afetados.
    • Execute a verificação de vulnerabilidade na mesma vulnerabilidade em todos os ativos de TI.
    • A estratégia a ser aplicada requer discussão entre SOC, gerenciamento de riscos e equipes de negócios.
    • Para falsos positivos, registre como estatísticas.


002. **New vulnerability from Threat Intelligence** / **Nova vulnerabilidade do Threat Intelligence**

*Sem dúvida, o que você mais executará, uma nova vulnerabilidade da inteligência de ameaças.

**Detecção**:

    • A inteligencia de ameaça indica que há uma nova vulnerabilidade afetando seus ativos.
    • Incluir apenas informações relevantes para seus ativos
    • Um inventário precisa e atualizado signifiva a importancia de manter em ordem.

**Verificação**:

    • Se houver IOC/TTP,verifique se os ataques já aconteceram. Se o ataque já aconteceu,siga o nº 1.
    • Use informações de versão/configuração vulneráveis para confirmar que os ativos são vulneráveis ou não.
    • Verifique as regras de firewall, para confirmar possiveis vetores de ataques
    • Isso pode ser feito parcialmente usando ferramentas automatizadas.

**Comunicação**:

    • Iniciar a triagem usando informações disponíveis sobre vulnerabilidade e criticidade de ativos.
    • Realizar escalonamento de acordo com os resultados da triagem e plano de escalonamento predefinido.
    • Discutir a estratégia de mitigação entre as equipes de SOC, gerenciamento de riscos e suporte de TI.
    • A estratégia de mitigação também precisa incluir ações preventivas para novas compilações de ativos no futuro, como atualizar o nível de patch de imagens ou modelos do sistema.

**Ação**:

    • Executar a estratégia de mitigação acordada.
    • Acompanhar as ações de mitigação até a conclusão.
    • Examine novamente a vulnerabilidade para confirmar o fechamento.

003. **Unauthorized privileged access** / **Acesso privilegiado não autorizado**

*Muitas organizações estão usando sistemas de gerenciamento de acesso privilegiado e podemos fazer uso dele para identificar o uso não autorizado, o que é muito útil para detectar credenciais roubadas.

**Detecção**:

    • Correlacione log de gerenciamento de acesso privilegiado (PAM) com logs de autenticação de pontos de extremidade relevantes. Dispare alertas em qualquer logon de conta privilegiada sem uma entrada de aprovação PAM correspondente.
    • Dispare alertas em qualuqer logon de conta privilegiada sem uma entrada de aprovação PAM correspondente.
    • Embora sejam acessos não autorizados, nem sempre podem ser ataques. Por exemplo, se o PAM não estiver definido para redefinir a senha após cada uso, a administração do sistema poderá memorizar a senha e usá-la para fazer logon várias vezes, ou pode haver scripts usando essas credenciais para fazer logon. No entanto, esses alertas serão úteis para a higiene cibernética e lembrarão gentilmente as pessoas sobre o uso adequado de contas privilegiadas.

**Verificação**:

    • Verifique com os administradores de sistema relevantes se eles usaram as contas no tempo relevante. Se nenhum administrador souber do uso, amplie a colaboração para equipes de suporte a aplicativos relacionados. Se ainda não houver conclusão, trate como ataque bem-sucedido e siga o nº 1.

**Comunicação**:

    • Para não ataques, reporte às equipes de segurança/gerenciamento de riscos e equipes de TI relevantes para resolver o uso indevido das contas em questão.

**Ação**:

    • Se houver exceções aceitas pelo risco, atualize as regras de correlação.


004. **Phishing email** / **E-mail de phishing**

*Aqui lidamos com e-mails de phishing com carga útil ou links maliciosos. Aqueles com conteúdo de texto apenas (por exemplo, golpes de contas a pagar) podem ser tratados com outra cartilha mais simples.

**Detecção**:

    • Alerta da solução de segurança de e-mail.
    • As soluções de segurança de e-mail são boas para bloquear e-mails de phishing quando veem um. O problema é que muitos adversários agora usam uma tática para evitá-los:
    i. Prepare um e-mail de phishing com um link apontando para nada, ou melhor ainda para uma página normal e inofensiva.
    ii. Envie o e-mail de phishing fora do horário comercial, ultrapassando-o pelos controles de segurança de e-mail e esperando que o destinatário ainda não esteja lá para abri-lo.
    iii. No início do dia, coloque conteúdo malicioso no site vinculado.
    iv. O usuário final começa a verificar e-mails e clicar no link agora malicioso.
    • As soluções de segurança de e-mail podem verificar os links passados por elas periodicamente para mitigar isso, mas sempre haverá um intervalo de tempo entre a verificação e o usuário clicar no link.
    • Alerta de pontos finais rastreados até a carga útil de e-mail/link de phishing.
    • Relatório de usuários finais.

**Verificação**:

    • Verifique se há e-mails semelhantes (por exemplo, mesmo servidor de e-mail de origem) entregues em outras caixas de entrada.  
    • Se o proxy da Web for imposto para solicitações da Web de saída, verifique os logs do proxy da Web para confirmar se o link mal-intencionado foi visitado. O usuário também deve ser contatado para entender se o link foi encaminhado para outros lugares (por exemplo, e-mail pessoal) e potencialmente clicado lá.
    • Verifique se o ponto final está isento de proxy web ou isolamento web. Nesse caso, outros logs (por exemplo, logs de firewall) precisam ser verificados para verificar se o link foi clicado ou não.• Se o link for visitado, verifique o log de proxy da Web para qualquer coisa baixada para o ponto final.
    • Se houver arquivos baixados, verifique se há ações maliciosas em eventos de segurança de endpoint e a análise de malware também é recomendada. Seu fornecedor de XDR deve ser capaz de realizar a análise se você não tiver um especialista interno nisso.
    • Muitas vezes é muito tentador apenas executar uma varredura AV ou carregar os arquivos baixados para o total de vírus para verificar se o ponto de extremidade está limpo ou não. Infelizmente, eles não são muito eficazes se os adversários não estiverem usando vulnerabilidades bem conhecidas ou código malicioso. Isso é especialmente verdadeiro para o spear phishing, onde tudo é personalizado.

**Comunicação**:

    • Siga a cartilha nº 1 se houver um compromisso confirmado.
    • Feedback para o usuário final que recebe o e-mail de phishing sobre a ação tomada (não clicou no link, relatou ao SOC, etc.).
    • Reporte às equipes de segurança/gerenciamento de risco sobre o escopo do phishing e aconselhe a comunicação geral a todos se isso parecer uma campanha de phishing.

**Ação**:

    • Siga a cartilha nº 1 se houver um comprometimento confirmado.
    • Exclua todos os e-mails de phishing de outras caixas de entrada (ou aconselhe os usuários finais a excluí-los).
    • Aciona a reconstrução do ponto de extremidade se você não tiver certeza do conteúdo baixado.
    • Revisite os controles de mitigação de phishing, como filtragem da Web (novos domínios, endereços IP), isolamento da Web/sandboxing, segurança de e-mail (DMARC) e conscientização de segurança do usuário final para ver se alguma melhoria é necessária.

005. **Confidential data on Internet** / **Dados confidenciais na Internet**

*Ele descreve o que fazer em dados notáveis descobertos por inteligência de ameaças na Internet.

***Detecção**:

    • A inteligência de ameaças encontrou dados não públicos sobre sua organização na Internet, como em buckets abertos do S3, Pastebin ou até mesmo diretórios "ocultos" em seu próprio servidor Web.
    • Denúncia de pessoas através de canais públicos e internos.

**Verificação**:

    • Faça o download de um instantâneo dos dados a serem verificados.
    • Identificar o potencial proprietário dos dados e entrar em contato com as equipes de negócios relevantes para revisar os dados. Somente o titular dos dados pode confirmar se os dados são genuínos e destinados ao consumo público ou não.

**Comunicação**:

    • Se for confirmado um vazamento, alerte as equipes de negócios relevantes e a equipe de segurança/gerenciamento de riscos.
    • Obtenha instruções das equipes de negócios sobre se as funções legais, de conformidade, de ligação com a aplicação da lei e outras funções de controle devem ser envolvidas para as próximas etapas. (por exemplo, vazamento de dados sensíveis ao preço das ações ou dados pessoais de funcionários ou clientes podem ter requisitos legais e regulamentares de relatórios).

**Ação**:

    • Remova os dados confidenciais se estiverem sob seu controle (por exemplo, em sua própria locação ou servidores web).
    • Caso contrário, use todos os canais disponíveis para retirar os dados confidenciais o mais rápido possível. Isso inclui serviços de proteção de marca, CERT nacional, contato de abuso do provedor de serviços de hospedagem ou até mesmo contatos de segurança pessoal que você tem com a organização de hospedagem. A eficácia de cada canal difere em quase todos os casos, por isso vale a pena tentar todos eles antes de recorrer a ações judiciais.
    • Descubra quem já baixou os dados.
    • Se os dados contiverem credenciais de autenticação, altere-as imediatamente.
    • Reporte ao proprietário dos dados após a conclusão da retirada.
    • Continuar a monitorar os dados por um período. Repita as ações de remoção se ele ressurgir.


006. **Fraudulent Websites** / **Sites fraudulentos**

*Eles fingem ser sua organização e tentam espalhar informações falsas, coletar dados de seus clientes, espalhar software mal-intencionado ou mais.

**Detecção**:

    • Alertas de serviço de proteção de marca.
    • Inteligência de ameaças.
    • Na minha experiência, não há nenhum mecanismo de detecção perfeito para sites fraudulentos. Alguns podem ser encontrados por pesquisas na web, alguns por serviços de proteção de marca e alguns são relatados apenas por clientes e terceiros. Ao coletar informações sobre ameaças, esteja ciente das limitações de linguagem dos mecanismos de busca e dos diferentes meios de comunicação que espalham os sites fraudulentos. Isso pode incluir e-mail e mensagens instantâneas.
    
**Verificação**:

    • Faça o download de uma cópia detalhada do site fraudulento. Diferencie entre conteúdo hospedado externamente e conteúdo de passagem no site original.
    • Tire capturas de tela do site fraudulento também. É útil incluir a captura de tela nas comunicações e como um registro no caso de o site ficar offline rapidamente.
    • Navegue no site fraudulento e confirme se ele:
    I. Contém informações falsas (por exemplo, e-mail de contato e números de telefone)
    II. Coletar informações do cliente (credenciais e dados pessoais)
    III. Contenham código malicioso (por exemplo, CSRF, downloads drive-by)

**Comunicação**:

    • Informe a equipe de conformidade sobre os relatórios regulatórios necessários.
    • Trabalhar com a ligação policial em relatórios policiais.
    • Discutir com a equipe de segurança e equipe de comunicação corporativa sobre o impacto do site fraudulento para os clientes e publicar alertas de clientes de acordo. Devem ser dados conselhos sobre as ações que precisam ser tomadas (por exemplo, alterar credenciais). Deve haver um canal de comunicação pré-definido, como SMS, site e press release.

**Ação**:

    • Invocar o serviço de proteção da marca e outros canais para retirar o site do ar (ver nº 5).
    • Continue a monitorar a URL por um período. Repita as ações de remoção se ele ressurgir.
    • Devido às incertezas sobre a conclusão da remoção do ar, muitas vezes observa-se que esses sites fraudulentos ficaram on-line e offline algumas vezes antes de caírem mortos para sempre.
  
007. **Brute Force Authentication** / **Autenticação por Força Bruta**

*Os ataques podem ser contra sistemas internos ou voltados para a Internet.

**Detecção**:

    • Alertas SIEM sobre o número de tentativas de autenticação com falha.
    • Alertas relacionados de IPS e outros dispositivos de segurança.

**Verificação**:

    • Verifique se o logon foi bem-sucedido ou não.• Confirme se a(s) conta(s) de destino existe ou não.• Verifique o IP de origem do ataque:
    i.Confirme se é um host interno ou externo ii. Confirme o proprietário/usuário do IP de origem (se possível)

**Comunicação**:

    • Se o ataque for bem-sucedido, escale para a equipe de gerenciamento de segurança/risco e equipes de suporte de TI relevantes e discuta a estratégia de mitigação. Informe o(s) proprietário(s) da conta relevante(s) sobre o comprometimento da senha e a redefinição necessária.
    • Se o invasor for um IP interno, verifique com o proprietário/administrador para entender se alguma ação recente pode ter causado isso. (por exemplo, software baixado da Internet)
    • Para ataques com falha, reporte/escale de acordo com um limite pré-acordado (por exemplo, com base no número de contas afetadas, número de ataques, etc.).

**Ação**:

    • Se o ataque for bem-sucedido, redefina as senhas de todas as contas comprometidas imediatamente. Trate os anfitriões de destino como comprometidos e siga o nº       1. Deve-se tomar cuidado extra se a conta em questão for uma conta de administrador, onde será necessária uma investigação aprofundada sobre o impacto e as ações de contenção necessárias.
    • Se o IP do invasor for interno, assuma que ele está comprometido e execute o nº 1.
    • Se o invasor estiver na Internet, bloqueie o IP de origem no perímetro da rede. Você pode considerar denunciá-lo ao proprietário do IP/AS em seu contato de abuso.
    
    
008. **Ransomware**

*Ransomware tem sido a principal preocupação de segurança cibernética para muitas organizações nos últimos anos.

**Detecção**:

    • Detecção de rede em tráfegos de ataque (por exemplo, Eternal Blue)
    • Detecção de segurança de endpoint em comportamento anormal do programa ou COI.
    • Relatório do usuário final nas telas de Ransomware.

**Verificação**:

    • Verifique a inteligência de ameaças para encontrar uma correspondência para o Ransomware. Eles geralmente são bem conhecidos.
    • Verifique o SIEM e outras fontes de eventos de segurança para entender o quão difundido o Ransomware e o host estão se espalhando rapidamente.
    • Investigar qual ponto final foi o primeiro ponto de intrusão e a provável causa raiz.

**Comunicação**:

    • Escalar para equipes de segurança/gerenciamento de risco e equipes de TI relevantes para discutir a estratégia de contenção. As opções disponíveis podem ser contenção de XDR, contenção de rede, desligamento remoto ou até mesmo desligamento (parcial) da rede. A opção dependerá da prevalência da causa raiz, disponibilidade de solução rápida, dificuldades na contenção da rede, capacidade de administração remota e assim por diante.
    • Informar os usuários de ponto final afetados sobre a indisponibilidade do sistema.

**Ação**:

    • Conter os pontos de extremidade infectados imediatamente. Desligue-os, se possível.
    • Se o backup estiver disponível para todos os sistemas afetados, reconstrua-os a partir da última cópia em boas condições.• Já deve ser bem conhecido que um espelho de dados on-line não pode remediar o risco de Ransomware, pois a cópia também pode ser corrompida.
Somente uma cópia offline com um cronograma de retenção adequado pode ser protegida contra adulteração e deve ser obrigatória em todos os dados.
    • Acompanhe a causa raiz da infecção pelo Ransomware e acompanhe sua remediação.
    
    
