from main import *
from _app.freeipa import *
from _app.source_user import *

logger = get_logger(__name__, get_file_name(f'{freeipa_stand}_adduser_full', 'log', 'adduser_full/log'), 'DEBUG',
                    'DEBUG')


def load_source_users_df(file_name, sheet_name='add'):
    '''Загрузка данных из шаблонного Excel с листа ADD'''

    source_users_list = get_execl_df(file_name, sheet_name)

    # Проверка на плохой формат оставшихся данных
    errors = {}
    for column in ['Фамилия', 'Имя', 'Отчество', 'Email', 'Логин', 'Телефон']:  # 'Должность'
        err = source_users_list[column][source_users_list[column].str.contains("\s", regex=True)]
        if not err.empty:
            pass
            # закомментировать, если в имени есть пробел
            errors.update({column: {key + 2: value for key, value in err.items()}})
    if errors:
        logger.error(f'\nОшибки формата данных (номер строки: значение):')
        for e in errors:
            logger.error(f'\t{e}: {errors[e]}')
        exit()

    return source_users_list


def set_fi_pager(fi_user: FreeIPAUser, pager_num: str, action: str = 'add'):
    """freeipa edit pager"""
    pagers = []
    try:
        pagers = list(fi_user.pager) if fi_user.pager else list()

        login = fi_user.uid
        if action == 'add':
            pagers.append(pager_num)
        elif action == 'replace':
            pagers = [pager_num]

        fi_conn.user_mod(a_uid=login, o_pager=pagers)
        logger.info(f'Обновлен Pager Number: {pagers}')

    except Exception as err_pager:
        if str(err_pager) == 'no modifications to be performed':
            logger.warning(f'Задача "{pager_num}" уже добавлена в Pager Number: {pagers}')
        else:
            logger.error(f'Ошибка обновления Pager Number на "{pagers}": {err_pager}', exc_info=True)


def set_fi_password(login: str, password: str):
    """Меняем транспортный пароль на постоянный или сохраняем ошибку и идем дальше"""
    change_password_result = 'OK'
    try:
        new_password = password or get_password()
        fi_conn.user_mod(a_uid=login, o_userpassword=new_password)
        fi_conn.change_password(login, new_password, new_password)
    except Exception as err_pwd:
        new_password = password
        change_password_result = f'Error: {error_html_parse(err_pwd)}'
    return new_password, change_password_result


def set_fi_groups(login: str, groups: list):
    """Добавляем группы, если они заполнены в шаблоне, или сохраняем ошибку и идем дальше"""
    add_groups_errs = []
    if groups:
        for group in groups:
            try:
                fi_conn.group_add_member(a_cn=group, o_user=login)
            except Exception as err_grp:
                add_groups_errs.append(f'{err_grp}')

    return 'OK' if not add_groups_errs else f'Error: {", ".join(add_groups_errs)}'


def set_fi_user(src_user: SourceUser):
    try:
        user = fi_conn.user_mod(a_uid=src_user.login,
                                o_givenname=src_user.given_name,
                                o_sn=src_user.last_name,
                                o_cn=src_user.full_name,
                                o_displayname=src_user.full_name,
                                o_title=src_user.title,
                                o_mail=src_user.email,
                                o_telephonenumber=src_user.phone,
                                o_ou=src_user.org_unit
                                )
    except ex.BadRequest as err:
        if err == 'no modifications to be performed':
            pass


def freeipa_process(src_user: SourceUser, user_log: dict):
    logger.debug(f'freeipa_process')

    # Поиск пользователя по логину в FreeIPA
    try:
        fi_user = FreeIPAUser(fi_conn.user_show(a_uid=src_user.login)['result'])
    except ex.NotFound:
        fi_user = FreeIPAUser()

    # Обнуление переменных
    password = change_password_result = add_groups_result = status = None

    try:
        if not fi_user.uid:
            # Пользователь не найден

            # Создаем пользователя
            user = fi_conn.user_add(a_uid=src_user.login,
                                    o_mail=src_user.email,
                                    o_givenname=src_user.given_name,
                                    o_sn=src_user.last_name,
                                    o_cn=src_user.full_name,
                                    o_title=src_user.title,
                                    o_telephonenumber=src_user.phone,
                                    o_pager=src_user.pager,
                                    o_ou=src_user.org_unit
                                    )
            fi_user_new = FreeIPAUser(user['result'])

            # Меняем транспортный пароль на постоянный или сохраняем ошибку и идем дальше
            password, change_password_result = set_fi_password(fi_user_new.uid, src_user.password)

            # Если группы заполнены в шаблоне - создаем их или сохраняем ошибку и идем дальше
            add_groups_result = set_fi_groups(fi_user_new.uid, src_user.freeipa_groups)

            status = 'Создан'

        else:
            # Пользователь найден

            # Проверяем архивность пользователя и разархивируем
            if fi_user.preserved:
                try:
                    fi_conn.user_undel(a_uid=fi_user.uid)
                    status = 'Разархивирован'
                except ex.BadRequest:
                    pass

            # Проверяем заблокированность и активируем
            if fi_user.nsaccountlock:
                try:
                    fi_conn.user_enable(a_uid=fi_user.uid)
                    status = f'{status}, активирован' if status else 'Активирован'
                except ex.AlreadyActive:
                    pass

            # Если группы заполнены в шаблоне - создаем их или сохраняем ошибку и идем дальше
            add_groups_result = set_fi_groups(fi_user.uid, src_user.freeipa_groups)

            # Обновление данных
            if src_user.freeipa_need_update:
                set_fi_user(src_user)

            # Меняем транспортный пароль на постоянный или сохраняем ошибку и идем дальше
            if fi_user.preserved or fi_user.nsaccountlock:
                password, change_password_result = set_fi_password(fi_user.uid, src_user.password)

            # Добавляем Pager Number
            if fi_user.preserved or fi_user.nsaccountlock or src_user.freeipa_need_update:
                set_fi_pager(fi_user, src_user.pager)

            status = status if status else 'Существует'

        fi_user_chg = FreeIPAUser(fi_conn.user_show(a_uid=src_user.login)['result'])

        user_log.update({'FreeIPA Статус': status,
                         'FreeIPA Логин': fi_user_chg.uid,
                         'FreeIPA Displayname': fi_user_chg.displayname,
                         'FreeIPA Email': fi_user_chg.mail,
                         'FreeIPA OrgUnit': fi_user_chg.ou,
                         'FreeIPA PagerNumber': src_user.pager,
                         'FreeIPA Пароль': password,
                         'FreeIPA Смена пароля': change_password_result,
                         'FreeIPA Result Groups': fi_user_chg.memberof_group,
                         'FreeIPA Добавление групп': add_groups_result
                         })
    except Exception as err:
        # Обработка ошибки, сохраняем текст, выполнение не прерываем
        user_log.update({'FreeIPA Статус': 'Ошибка',
                         'FreeIPA Error': str(err)})


def keycloack_process(src_user: SourceUser, user_log: dict, keycloack_groups_dict):
    logger.debug(f'keycloack_process')

    # Поиск пользователя по логину в Keycloak
    kc_user_id = None
    kc_groups = {}
    try:
        kc_user_id = kc_conn.get_user_id(username=src_user.login)
        kc_user = kc_conn.get_user(user_id=kc_user_id)
        kc_groups = kc_conn.get_user_groups(kc_user_id)
    except Exception as err:
        if str(err) != "404: b''":
            logger.debug(f'keycloack search {src_user.login}: {err}')
        kc_user = None

    try:
        status = None
        if not kc_user:
            # Пользователь не найден

            # Создаем пользователя
            kc_user_id = kc_conn.create_user(payload={"username": src_user.login,
                                                      "firstName": src_user.given_name,
                                                      "lastName": src_user.last_name,
                                                      "email": src_user.email,
                                                      "enabled": True,
                                                      "requiredActions": ["UPDATE_PASSWORD"],
                                                      "credentials": src_user.keycloack_credentional,
                                                      "groups": src_user.keycloack_groups
                                                      },
                                             exist_ok=False
                                             )

            for grp in keycloack_groups_dict:
                if grp['name'] in src_user.keycloack_groups:
                    kc_conn.group_user_add(kc_user_id, grp['id'])

            status = 'Создан'
        else:
            for grp in keycloack_groups_dict:
                if grp['name'] in src_user.keycloack_groups:
                    kc_conn.group_user_add(kc_user_id, grp['id'])

            status = status if status else 'Существует'

        fi_user_chg = kc_conn.get_user(user_id=kc_user_id)
        fi_user_grps_chg = [g['name'] for g in kc_conn.get_user_groups(kc_user_id)]

        user_log.update({'KeyCloack Статус': status,
                         'KeyCloack Displayname': f'{fi_user_chg["lastName"]} {fi_user_chg["firstName"]}',
                         'KeyCloack Email': fi_user_chg["email"],
                         'KeyCloack Result Groups': fi_user_grps_chg
                         })

    except Exception as err:
        # Обработка ошибки, сохраняем текст, выполнение не прерываем
        user_log.update({'KeyCloack Статус': 'Ошибка',
                         'KeyCloack Error': str(err)}
                        )


def roles_by_matrix_process(src_user: SourceUser, user_log: dict):
    logger.debug(f'roles_by_matrix_process')

    user_log.update({'RolesByMatrix Статус': 'Ошибка',
                     'RolesByMatrix Error': str('err')}
                    )


def main():
    # Определение переменной для вывода итоговой таблицы
    users_result = pd.DataFrame()

    # Загрузка данных из шаблонного Excel с листа ADD
    source_users_df = load_source_users_df(file_name='../_src/users_template.xlsx')

    # Преобразование Excel в массив пользователей (SourceUser[])
    source_users = get_source_users(source_users_df)

    # Справочник групп KeyCloack
    keycloack_groups_dict = kc_conn.get_groups()
    print(keycloack_groups_dict)

    # Цикл по списку пользователей
    for index, src_user in enumerate(source_users):
        logger.info(f'{index}. {src_user.login}')
        logger.debug(f'{src_user.__dict__}')

        user_log = {'Логин': src_user.login,
                    'FreeIPA': src_user.need_freeipa,
                    'KeyCloack': src_user.need_keycloack,
                    'RolesByMatrix': src_user.need_role_by_matrix,
                    'Фамилия': src_user.last_name,
                    'Имя': src_user.first_name,
                    'Отчество': src_user.second_name,
                    'Displayname': src_user.full_name,
                    'Email': src_user.email,
                    'OrgUnit': src_user.org_unit,
                    'PagerNumber': src_user.pager,
                    'Пароль': src_user.password,
                    'Пароль сгенерирован': src_user.password_gererated,
                    'Телефон': src_user.phone,
                    'Должность': src_user.title,
                    'FreeIPA Groups': src_user.freeipa_groups,
                    'FreeIPA Обновить данные': src_user.freeipa_need_update,
                    'KeyCloack Groups': src_user.keycloack_groups,
                    }

        if src_user.need_freeipa:
            freeipa_process(src_user, user_log)
        else:
            user_log.update({'FreeIPA Статус': ''})

        if src_user.need_keycloack:
            keycloack_process(src_user, user_log, keycloack_groups_dict)
        else:
            user_log.update({'KeyCloack Статус': ''})

        if src_user.need_role_by_matrix:
            roles_by_matrix_process(src_user, user_log)
        else:
            user_log.update({'RolesByMatrix Статус': ''})

        logger.debug(user_log)
        # Сохраняем обработанного пользователя в результирующий набор
        users_result = users_result.append(user_log, ignore_index=True)

    logger.info(f'\n{users_result.fillna("")}')

    df_first_columns = ['Логин', 'FreeIPA', 'FreeIPA Статус', 'KeyCloack', 'KeyCloack Статус', 'RolesByMatrix',
                        'RolesByMatrix Статус']
    df_columns = list(users_result.keys())
    for col_name in reversed(df_first_columns):
        try:
            df_columns.pop(list.index(df_columns, col_name))
            df_columns.insert(0, col_name)
        except:
            pass

    # Сохраняем результирующий набор в Excel (перечисленный список полей)
    users_result.to_excel(get_file_name(f'{freeipa_stand}_adduser_full', 'xlsx', 'adduser_full'), sheet_name='result',
                          columns=df_columns,
                          index=False)


if __name__ == '__main__':
    prepare()

    # авторизация в FreeIPA
    fi_conn = get_connection_freeipa()
    if not fi_conn: exit()

    # авторизация в KeyCloak
    kc_conn = get_connection_keycloak()
    if not kc_conn: exit()

    main()
