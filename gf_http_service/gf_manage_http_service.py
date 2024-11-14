#!/usr/bin/python

"""
Módulo Ansible para gerenciar propriedades do serviço HTTP em uma configuração de domínio.

Este módulo permite configurar e verificar as propriedades `accessLoggingEnabled` e `ssoEnabled`
do serviço HTTP em um domínio específico via uma API REST. Ele obtém as configurações atuais
do serviço HTTP e aplica alterações se os valores diferirem dos desejados.

Funções principais:
    - get_http_service: Obtém as configurações atuais de `accessLoggingEnabled` e `ssoEnabled`.
    - ensure_http_service: Verifica as configurações e realiza uma atualização POST se necessário.
"""

import requests
from ansible.module_utils.basic import AnsibleModule
from requests.auth import HTTPBasicAuth


def get_http_service(module, url, auth, headers):
    """
    Realiza uma solicitação GET para obter as configurações atuais de `accessLoggingEnabled` e `ssoEnabled`.

    Args:
        module (AnsibleModule): Instância do módulo Ansible atual, usada para acessar parâmetros e gerar saídas.
        url (str): URL do serviço HTTP a ser consultado.
        auth (HTTPBasicAuth): Objeto de autenticação com credenciais de administrador.
        headers (dict): Cabeçalhos HTTP a serem usados na solicitação.

    Returns:
        dict: Dicionário contendo os valores atuais de `accessLoggingEnabled` e `ssoEnabled`.

    Raises:
        module.fail_json: Se ocorrer uma exceção durante a solicitação HTTP.
    """
    try:
        response = requests.get(
            url,
            auth=auth,
            headers=headers,
            verify=module.params['validate_certs'],
        )
        response.raise_for_status()
        data = response.json()

        # Mostra o JSON completo retornado para debugging
        module.debug(msg=f'GET response data: {data}')

        # Obtém os parâmetros atuais de `accessLoggingEnabled` e `ssoEnabled`
        http_service = data.get('extraProperties', {}).get('entity', {})

        # Mostra o conteúdo de http_service para debugging
        module.debug(msg=f'Current HTTP service properties: {http_service}')

        return {
            'access_logging_enabled': http_service.get('accessLoggingEnabled'),
            'sso_enabled': http_service.get('ssoEnabled'),
        }
    except requests.RequestException as e:
        module.fail_json(
            msg=f'Failed to get HTTP service properties. Error: {str(e)}'
        )


def ensure_http_service(
    module, url, auth, headers, desired_access_logging, desired_sso
):
    """
    Verifica as configurações atuais e realiza uma atualização POST se os valores forem diferentes dos desejados.

    Args:
        module (AnsibleModule): Instância do módulo Ansible atual, usada para acessar parâmetros e gerar saídas.
        url (str): URL do serviço HTTP para verificar e atualizar configurações.
        auth (HTTPBasicAuth): Objeto de autenticação com credenciais de administrador.
        headers (dict): Cabeçalhos HTTP para as solicitações.
        desired_access_logging (str): Valor desejado para `accessLoggingEnabled`.
        desired_sso (str): Valor desejado para `ssoEnabled`.

    Returns:
        bool: Indica se uma mudança foi aplicada (`True`) ou se já estava conforme (`False`).

    Raises:
        module.fail_json: Se ocorrer uma falha ao tentar atualizar o serviço HTTP.
    """
    changed = False
    current_http_service = get_http_service(module, url, auth, headers)

    # Verifica se os valores atuais são diferentes dos valores desejados e registra no debug
    if (
        current_http_service['access_logging_enabled']
        != desired_access_logging
    ):
        module.debug(
            msg=f"access_logging_enabled: current={current_http_service['access_logging_enabled']}, desired={desired_access_logging}"
        )
        changed = True
    if current_http_service['sso_enabled'] != desired_sso:
        module.debug(
            msg=f"sso_enabled: current={current_http_service['sso_enabled']}, desired={desired_sso}"
        )
        changed = True

    if changed:
        # Monta o payload para atualizar as configurações
        payload = {
            'accessLoggingEnabled': desired_access_logging,
            'ssoEnabled': desired_sso,
        }

        # Mostra o payload que será enviado no POST
        module.debug(msg=f'POST payload: {payload}')

        response = requests.post(
            url,
            json=payload,
            auth=auth,
            headers=headers,
            verify=module.params['validate_certs'],
        )
        if response.status_code == 200:
            module.debug(msg=f'Updated HTTP service properties successfully.')
        else:
            module.fail_json(
                msg=f'Failed to update HTTP service properties. Status code: {response.status_code}, Response: {response.text}'
            )

    return changed


def main():
    """
    Ponto de entrada principal para o módulo Ansible.

    Define os argumentos do módulo, inicializa a instância AnsibleModule e executa
    o fluxo de verificação e atualização das configurações de `accessLoggingEnabled` e `ssoEnabled`.

    Parâmetros:
        - target (str): Identificação do alvo de configuração.
        - domain_host (str): Host do domínio onde o serviço HTTP está sendo gerenciado.
        - admin_port (int): Porta administrativa para conexão ao domínio.
        - admin_user (str): Nome de usuário para autenticação.
        - admin_pass (str): Senha para autenticação.
        - validate_certs (bool): Indica se certificados SSL devem ser validados.
        - protocol (str): Protocolo HTTP ou HTTPS.
        - access_logging_enabled (str): Estado desejado para `accessLoggingEnabled`.
        - sso_enabled (str): Estado desejado para `ssoEnabled`.

    Executa a função `ensure_http_service` para verificar e aplicar mudanças, e
    exibe a mensagem final, indicando se houve alterações aplicadas.
    """
    module_args = dict(
        target=dict(type='str', required=True),
        domain_host=dict(type='str', required=True),
        admin_port=dict(type='int', required=True),
        admin_user=dict(type='str', required=True),
        admin_pass=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', default=False),
        protocol=dict(type='str', default='https', choices=['http', 'https']),
        access_logging_enabled=dict(type='str', required=True),
        sso_enabled=dict(type='str', required=True),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    domain_host = module.params['domain_host']
    admin_port = module.params['admin_port']
    admin_user = module.params['admin_user']
    admin_pass = module.params['admin_pass']
    validate_certs = module.params['validate_certs']
    protocol = module.params['protocol']
    access_logging_enabled = module.params['access_logging_enabled']
    sso_enabled = module.params['sso_enabled']
    target = module.params['target']

    # Construir a URL correta para o http-service baseado no alvo
    url = f'{protocol}://{domain_host}:{admin_port}/management/domain/configs/config/{target}-config/http-service'
    auth = HTTPBasicAuth(admin_user, admin_pass)
    headers = {
        'Accept': 'application/json',
        'X-Requested-By': 'GlassFish REST HTML interface',
    }

    # Verificar e garantir que as propriedades do HTTP service estão corretas
    changed = ensure_http_service(
        module, url, auth, headers, access_logging_enabled, sso_enabled
    )

    # Exibe a mensagem final, indicando se houve mudanças
    module.exit_json(changed=changed, msg='HTTP service properties managed.')


if __name__ == '__main__':
    main()
