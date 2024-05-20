**O que faz essa aplicação?**

Monitoramento em Tempo Real : Uma aplicação que captura e exibe o tráfego de rede em tempo real, permitindo que os usuários visualizem a quantidade de pacotes de dados sendo transmitidos.

Identificação de Dispositivos : Através de varreduras ARP, ela identifica e lista todos os dispositivos conectados à rede, mostrando informações como IP, nome (sistema operacional), tipo de dispositivo e dados consumidos em MB.

Registro de Atividades : Todos os pacotes capturados são registrados em um arquivo de log, fornecendo uma análise detalhada para auditorias e diagnósticos futuros.

Utilidade de Aplicação
Gestão de Redes Domésticas e Empresariais : Ideal para administradores de rede que precisam monitorar o uso de dados e identificar dispositivos conectados.

Análise de Tráfego : Permite uma visão clara do tráfego de rede, ajudando a identificar picos de uso e possíveis gargalos.

Segurança de Rede : Ao visualizar dispositivos conectados e seu consumo de dados, é possível detectar atividades suspeitas e dispositivos não autorizados.

***Importante: Considerações sobre Privacidade e LGPD***
Embora essa ferramenta seja extremamente útil, é crucial destacar que ela deve ser utilizada apenas em redes privadas e com consentimento explícito de todos os usuários da rede . A Lei Geral de Proteção de Dados (LGPD) no Brasil e outras regulamentações globais de privacidade impedem que dados pessoais sejam protegidos e que a coleta e o processamento de dados sejam feitos de forma transparente e legal.

Não utilize esta aplicação em redes públicas ou sem autorização , pois a captura de tráfego de dados pode expor informações pessoais sensíveis, infringindo a privacidade dos usuários e a conformidade legal.

***Reflexão sobre Privacidade***
A privacidade e a proteção de dados são pilares fundamentais na era digital. Ferramentas de monitoramento, quando usadas de forma ética e responsável, podem fortalecer a segurança das redes, mas é vital que todos os aspectos legais e éticos sejam respeitados.

Estou à disposição para discutir mais sobre este projeto e a importância da privacidade de dados. Vamos juntos construir um ambiente digital mais seguro e consciente!

***Pontos Importantes:***
Para executar o script e realizar alterações em python é necessário que você realiza os seguintes imports caso não tenha configurado:

***tkinter, psutil, scapy, matplotlib,requests***
E tenha instalando também o aplicativo *npcap versão atual* que pode ser encontrado (https://npcap.com/), pois a aplicação utiliza essa API para fazer o scan na rede.
