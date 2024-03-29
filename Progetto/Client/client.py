import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox, Listbox, Scrollbar, Entry, IntVar
import requests
import re
import json
from OpenSSL import crypto
from urllib3.exceptions import InsecureRequestWarning
from email.utils import parseaddr


class User:
    def __init__(self, username, token, email):
        self.username = username
        self.token = token
        self.email = email

    def set_user(self, username, token, email):
        self.username = username
        self.token = token
        self.email = email

    def setToken(self, token):
        self.token = token

    def getToken(self):
        return self.token

    def setUsername(self, username):
        self.username = username

    def getUsername(self):
        return self.username

    def setEmail(self, email):
        self.email = email

    def getEmail(self):
        return self.email

    def setNone(self):
        self.username = None
        self.email = None
        self.token = None


user = User("username", "token", "prova.prova@prova.prova")


def generate_self_signed_cert(cert_file, key_, days_valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "Client"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(days_valid * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        with open(cert_file, 'wb') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_, 'wb') as key_:
            key_.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    except Exception as e:
        print(e)


cert_ = './cert.pem'
key_file = './privkey.pem'
generate_self_signed_cert(cert_, key_file)


def is_valid_email(email):
    try:
        _, email_address = parseaddr(email)
        if re.match(r'[^@]+@[^@]+\.[^@]+', email_address):
            return True
        return False
    except Exception as err:
        print(err)
        return False


def accedi():
    try:
        username = entry_username.get()
        password = entry_password.get()
        url = "https://localhost:5000/login"
        payload = {'username': username, 'password': password}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            token = result['token']
            data_split = token.split('|')
            data = json.loads(data_split[0])
            user.set_user(data['username'], token, data['email'])
            mostra_menu()
            entry_username.delete(0, tk.END)
            entry_password.delete(0, tk.END)
        else:
            messagebox.showerror("Login", result['message'])
    except Exception as err:
        print("Login:", err)


def logout():
    try:
        url = "https://localhost:5000/logout"
        payload = {'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            force_logout()
            messagebox.showinfo("Logout", "Logout effettuato con successo")
        else:
            messagebox.showerror("Logout", "Errore durante il logout")
    except Exception as err:
        print(err)


def is_not_empty(field_value):
    return not bool(field_value.strip())


def has_no_spaces(input_string):
    return not ' ' not in input_string


def register():
    try:
        username = entry_username_2.get()
        email = entry_mail.get()
        password = entry_password_2.get()
        if is_not_empty(username) or is_not_empty(email) or is_not_empty(password):
            messagebox.showerror("Register", "Compilare tutti i campi")
            return
        if not is_valid_email(email):
            messagebox.showerror("Register", "Email non valida")
            return
        if has_no_spaces(username) or has_no_spaces(email) or has_no_spaces(password):
            messagebox.showerror("Register", "Non è possibile inserire spazi nei campi")
            return
        url = "https://localhost:5000/register"
        payload = {'username': username, 'email': email, 'password': password}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            switch_to_log()
            messagebox.showinfo("Register", "Registrazione avvenuta con successo")
            entry_username_2.delete(0, tk.END)
            entry_password_2.delete(0, tk.END)
            entry_mail.delete(0, tk.END)
        else:
            messagebox.showerror("Register", result['message'])
    except Exception as err:
        print(err)


def get_subscriptions():
    try:
        url = "https://localhost:8001/get_subscriptions"
        payload = {'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            mostra_elenco_topic(result['topics'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            messagebox.showerror("Errore", result['message'])
    except Exception as err:
        print(err)
        messagebox.showerror("Errore", "Subscriber non raggiungibile")


def my_subscriptions():
    try:
        url = "https://localhost:8001/my_subscriptions"
        payload = {'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            mostra_my_sub(result['topics'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            lista = []
            mostra_my_sub(lista)
    except Exception as err:
        print(err)
        messagebox.showerror("Errore", "Microservizio Subscriber non raggiungibile")


def mostra_menu():
    login_frame.pack_forget()
    menu_frame.pack()


def reverse_mostra_menu():
    menu_frame.pack_forget()
    login_frame.pack()


def open_update_menu():
    menu_frame.pack_forget()
    update_frame.pack()


def back_from_update_menu():
    update_frame.pack_forget()
    menu_frame.pack()


def switch_to_update_username():
    entry_old.config(state='normal')
    entry_old.delete(0, tk.END)
    entry_old.insert(0, user.getUsername())
    entry_old.config(state='readonly')
    update_frame.pack_forget()
    form_update_name.pack()


def force_logout():
    user.setNone()
    menu_frame.pack_forget()
    elenco_topic_frame.pack_forget()
    elenco_my_sub_frame.pack_forget()
    update_frame.pack_forget()
    form_update_email.pack_forget()
    form_update_psw.pack_forget()
    form_update_name.pack_forget()
    login_frame.pack()


def back_to_menu_from_username():
    form_update_name.pack_forget()
    entry_new.delete(0, tk.END)
    entry_pass.delete(0, tk.END)
    update_frame.pack()


def switch_to_update_email():
    entry_old_email.config(state='normal')
    entry_old_email.delete(0, tk.END)
    entry_old_email.insert(0, user.getEmail())
    entry_old_email.config(state='readonly')
    update_frame.pack_forget()
    form_update_email.pack()


def back_to_menu_from_email():
    form_update_email.pack_forget()
    entry_new_email.delete(0, tk.END)
    entry_pass_email.delete(0, tk.END)
    update_frame.pack()


def switch_to_update_psw():
    update_frame.pack_forget()
    form_update_psw.pack()


def back_to_menu_from_psw():
    form_update_psw.pack_forget()
    entry_psw.delete(0, tk.END)
    entry_new_psw.delete(0, tk.END)
    update_frame.pack()


def switch_to_reg():
    login_frame.pack_forget()
    entry_username.delete(0, tk.END)
    entry_password.delete(0, tk.END)
    reg_frame.pack()


def switch_to_log():
    reg_frame.pack_forget()
    entry_username_2.delete(0, tk.END)
    entry_password_2.delete(0, tk.END)
    entry_mail.delete(0, tk.END)
    login_frame.pack()


def back_menu():
    elenco_topic_frame.pack_forget()
    menu_frame.pack()
    root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")


def back_menu_2():
    elenco_my_sub_frame.pack_forget()
    menu_frame.pack()
    tree.delete(*tree.get_children())
    root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")


def delete_items():
    try:
        selected_items = tree.selection()
        if not selected_items:
            return
        url = "https://localhost:8001/remove_subscription"
        list_sub = []
        for el in selected_items:
            item_text = tree.item(el, 'text')
            list_sub.append(item_text)
        payload = {'token': user.getToken(), 'sub_list': list_sub}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.delete(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            tree.delete(*tree.get_children())
            my_subscriptions()
            messagebox.showinfo("Operazione Delete", "Eliminazione effettuata con successo")
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            if len(selected_items) != 0:
                messagebox.showerror("Errore", "Errore durante la cancellazione delle sottoscrizioni")
            else:
                messagebox.showerror("Errore", "Errore durante la cancellazione della sottoscrizione")
    except Exception as err:
        messagebox.showerror("Errore", "Errore durante la cancellazione della sottoscrizione: ", err)


def update_items():
    selected_items = tree.selection()
    if not selected_items:
        return
    for item in selected_items:
        location = tree.item(item, 'text')
        t_min = tree.set(item, 'T_min')
        t_max = tree.set(item, 'T_max')
        um = tree.set(item, 'Humidity')
        pr = tree.set(item, 'Precipitation')
        data = (location, t_min, t_max, um, pr)
        new_form(data)


def mostra_elenco_topic(topics):
    menu_frame.pack_forget()
    elenco_topic_frame.pack()
    aggiorna_elenco_topic(topics)


def mostra_my_sub(topics):
    print(topics)
    menu_frame.pack_forget()
    elenco_my_sub_frame.pack()
    for i, el in enumerate(topics):
        data = (el['t_min'], el['t_max'], el['humidity'], el['precipitation'])
        tree.insert('', tk.END, iid=f"{i}", text=el['location'], values=data)
    for colonna in tree["columns"]:
        tree.column(colonna, stretch=True)
    altezza_widget = min(20, 8)
    tree["height"] = altezza_widget
    larghezza_widget = 400
    altezza_widget = 250
    x_2 = (schermo_larghezza - larghezza_widget) // 2
    y_2 = (schermo_altezza - altezza_widget) // 2
    num_topics = len(topics)
    if num_topics > 7:
        scrollbar_2.pack(side=tk.RIGHT, fill=tk.Y)
    else:
        scrollbar_2.pack_forget()
    root.geometry(f"{larghezza_widget}x{altezza_widget}+{x_2}+{y_2}")


def subscript(nome, t_min, t_max, hum, pre, window):
    try:
        if not validate_temperature(t_min) or not validate_temperature(t_max):
            messagebox.showwarning("Errore", "La temperatura deve essere compresa tra -10°C e 50°C ")
            window.lift()
            return
        if not validate_hp(hum) or not validate_hp(pre):
            messagebox.showwarning("Errore", "L'umidità e le precipitazioni deve essere compresa tra 0 e 100 ")
            window.lift()
            return
        url = "https://localhost:8001/subscript"
        payload = {'location': nome, 't_min': t_min, 't_max': t_max, 'humidity': hum, 'precipitation': pre, 'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.put(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            if tree.get_children():
                tree.delete(*tree.get_children())
                my_subscriptions()
            messagebox.showinfo("Subscription", result['message'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            messagebox.showerror("Subscription", result['message'])
        window.destroy()
    except Exception as err:
        print(err)


def aggiorna_elenco_topic(topics):
    listbox.delete(0, tk.END)  # Cancella gli elementi precedenti dalla Listbox
    for topic in topics:
        listbox.insert(tk.END, topic)


def validate_temperature(value):
    try:
        if value == "":
            return True
        if value[0] == '-':
            value = value[1:]
            if value.isdigit():
                temp = -float(value)
                print(temp)
                return -10 <= temp <= 50
    except Exception:
        return False
    if value.isdigit():
        try:
            temp = float(value)
            print(temp)
            return -10 <= temp <= 50
        except ValueError:
            return False
    else:
        return False


def validate_hp(value):
    try:
        if value == "":
            return True
        if '-' in value:
            return False
    except Exception:
        return False
    if value.isdigit():
        try:
            temp = float(value)
            return 0 <= temp <= 100
        except ValueError:
            return False
    else:
        return False


def on_select(event):
    selection = event.widget.curselection()
    if selection:
        index = selection[0]
        data = event.widget.get(index)
        new_form(data)


def update(password, val_new, data):
    try:
        print(password, val_new, data)
        if data == "email":
            if not is_valid_email(val_new):
                messagebox.showerror("Register", "Email non valida")
                return
        if is_not_empty(val_new):
            messagebox.showerror("Update", "Non è possibile lasciare i campi vuoti")
            return
        if has_no_spaces(val_new):
            messagebox.showerror("Update", "Non è possibile inserire spazi nei campi")
            return
        url = "https://localhost:5000/update"
        payload = {'val_new': val_new, 'password': password, 'update': data, 'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.put(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            if data == "email":
                user.setEmail(val_new)
                back_to_menu_from_email()
            elif data == "username":
                user.setUsername(val_new)
                back_to_menu_from_username()
            elif data == "password":
                back_to_menu_from_psw()
            user.setToken(result['token'])
            messagebox.showinfo("Update", result['message'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", result['message'])
                return
            messagebox.showerror("Update", result['message'])
    except Exception as err:
        print(err)


def reset_entry_value(entry, check_var):
    if check_var.get() == 1:
        entry.delete(0, tk.END)
        entry.config(state='disabled')
    else:
        entry.config(state='normal')


def new_form(data):
    form_window = tk.Toplevel(root)
    form_window.title("Richiedi sottoscrizione")
    form_window.geometry(f"{300}x{200}+{x}+{y}")
    label_nome = tk.Label(form_window, text="Nome:")
    entry_nome = Entry(form_window)
    if isinstance(data, tuple):
        entry_nome.insert(0, data[0])
    else:
        entry_nome.insert(0, data)
    entry_nome.config(state='readonly')
    label_temp_min = tk.Label(form_window, text="Temp Minima:")
    entry_temp_min = Entry(form_window)
    check_var_temp_min = IntVar()
    check_temp_min = tk.Checkbutton(form_window, text="Null", variable=check_var_temp_min,
                                    command=lambda: reset_entry_value(entry_temp_min, check_var_temp_min))
    if isinstance(data, tuple):
        if data[1] == "None":
            check_temp_min.toggle()
            entry_temp_min.insert(0, "")
            entry_temp_min.config(state='readonly')
        else:
            entry_temp_min.insert(0, data[1])
    label_temp_max = tk.Label(form_window, text="Temp Massima:")
    entry_temp_max = Entry(form_window)
    check_var_temp_max = IntVar()
    check_temp_max = tk.Checkbutton(form_window, text="Null", variable=check_var_temp_max,
                                    command=lambda: reset_entry_value(entry_temp_max, check_var_temp_max))
    if isinstance(data, tuple):
        if data[2] == "None":
            check_temp_max.toggle()
            entry_temp_max.insert(0, "")
            entry_temp_max.config(state='readonly')
        else:
            entry_temp_max.insert(0, data[2])
    label_um = tk.Label(form_window, text="Umidità:")
    entry_um = Entry(form_window)
    check_var_um = IntVar()
    check_um = tk.Checkbutton(form_window, text="Null", variable=check_var_um, command=lambda: reset_entry_value(entry_um, check_var_um))
    if isinstance(data, tuple):
        if data[3] == "None":
            check_um.toggle()
            entry_um.insert(0, "")
            entry_um.config(state='readonly')
        else:
            entry_um.insert(0, data[3])
    label_precipitazione = tk.Label(form_window, text="Precipitazione:")
    entry_precipitazione = Entry(form_window)
    check_var_precipitazione = IntVar()
    check_precipitazione = tk.Checkbutton(form_window, text="Null", variable=check_var_precipitazione, command=lambda: reset_entry_value(entry_precipitazione, check_var_precipitazione))
    if isinstance(data, tuple):
        if data[4] == "None":
            check_precipitazione.toggle()
            entry_precipitazione.insert(0, "")
            entry_precipitazione.config(state='readonly')
        else:
            entry_precipitazione.insert(0, data[4])
    button_confirm = tk.Button(form_window, text="Conferma", command=lambda: subscript(entry_nome.get(),
                                                                                       entry_temp_min.get(),
                                                                                       entry_temp_max.get(),
                                                                                       entry_um.get(),
                                                                                       entry_precipitazione.get(),
                                                                                       form_window))
    label_nome.grid(row=0, column=0, sticky=tk.E)
    entry_nome.grid(row=0, column=1, sticky=tk.W)

    label_temp_min.grid(row=1, column=0, sticky=tk.E)
    entry_temp_min.grid(row=1, column=1, sticky=tk.W)
    check_temp_min.grid(row=1, column=2, sticky=tk.W)

    label_temp_max.grid(row=2, column=0, sticky=tk.E)
    entry_temp_max.grid(row=2, column=1, sticky=tk.W)
    check_temp_max.grid(row=2, column=2, sticky=tk.W)

    label_um.grid(row=3, column=0, sticky=tk.E)
    entry_um.grid(row=3, column=1, sticky=tk.W)
    check_um.grid(row=3, column=2, sticky=tk.W)

    label_precipitazione.grid(row=4, column=0, sticky=tk.E)
    entry_precipitazione.grid(row=4, column=1, sticky=tk.W)
    check_precipitazione.grid(row=4, column=2, sticky=tk.W)

    button_confirm.grid(row=5, column=1, pady=10)

    blk = tk.Label(form_window, text=" ")
    blk.grid(row=6, column=0, columnspan=3)

root = tk.Tk()
root.title("Applicazione")
# Frame per il login
login_frame = tk.Frame(root)
blk_label = tk.Label(login_frame, text=" ")
blk_label.pack()
label_username = tk.Label(login_frame, text="Username:")
label_username.pack()
entry_username = tk.Entry(login_frame)
entry_username.pack()
label_password = tk.Label(login_frame, text="Password:")
label_password.pack()
entry_password = tk.Entry(login_frame, show="*")
entry_password.pack()
blk_label = tk.Label(login_frame, text=" ")
blk_label.pack()
button_login = tk.Button(login_frame, text="Accedi", command=accedi)
button_reg = tk.Button(login_frame, text="Registrati", command=switch_to_reg)
button_login.pack(side=tk.LEFT, padx=(0, 10))
button_reg.pack(side=tk.LEFT, padx=(10, 0))
login_frame.pack()
# Frame per la reg
reg_frame = tk.Frame(root)
blk_label = tk.Label(reg_frame, text=" ")
blk_label.pack()
label_username_2 = tk.Label(reg_frame, text="Username:")
label_username_2.pack()
entry_username_2 = tk.Entry(reg_frame)
entry_username_2.pack()
label_mail = tk.Label(reg_frame, text="Email:")
label_mail.pack()
entry_mail = tk.Entry(reg_frame)
entry_mail.pack()
label_password_2 = tk.Label(reg_frame, text="Password:")
label_password_2.pack()
entry_password_2 = tk.Entry(reg_frame, show="*")
entry_password_2.pack()
blk_label_2 = tk.Label(reg_frame, text=" ")
blk_label_2.pack()
button_login_2 = tk.Button(reg_frame, text="Accedi", command=switch_to_log)
button_reg_2 = tk.Button(reg_frame, text="Registrati", command=register)
button_reg_2.pack(side=tk.LEFT, padx=(0, 10))
button_login_2.pack(side=tk.LEFT, padx=(10, 0))
# Frame per il menu
menu_frame = tk.Frame(root)
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_subscription = tk.Button(menu_frame, text="Subscriptions", command=get_subscriptions)
button_subscription.pack()
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_subscription_active = tk.Button(menu_frame, text="MySubscriptions", command=my_subscriptions)
button_subscription_active.pack()
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_settings = tk.Button(menu_frame, text="Settings", command=open_update_menu)
button_settings.pack()
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_logout = tk.Button(menu_frame, text="Logout", command=logout)
button_logout.pack()
# Frame per l'elenco dei topic
elenco_topic_frame = tk.Frame(root)
button_back = tk.Button(elenco_topic_frame, text="Indietro", command=back_menu)
button_back.pack(side=tk.BOTTOM)
listbox = Listbox(elenco_topic_frame, selectmode=tk.SINGLE)
listbox.bind('<<ListboxSelect>>', on_select)  # Aggiungi un evento di selezione
scrollbar = Scrollbar(elenco_topic_frame, orient=tk.VERTICAL)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)
listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
# Frame per l'elenco my_sub
elenco_my_sub_frame = tk.Frame(root)
tree = ttk.Treeview(elenco_my_sub_frame, columns=("T_min", "T_max", "Humidity", "Precipitation"), height=20)
tree.heading('#0', text='Location', anchor=tk.CENTER)
tree.heading('T_min', text='T_min', anchor=tk.CENTER)
tree.heading('T_max', text='T_max', anchor=tk.CENTER)
tree.heading('Humidity', text='Humidity', anchor=tk.CENTER)
tree.heading('Precipitation', text='Precipitation', anchor=tk.CENTER)
# Allo stesso modo per le colonne
tree.column('#0', width=110, anchor=tk.CENTER)
tree.column('T_min', width=50, anchor=tk.CENTER)
tree.column('T_max', width=50, anchor=tk.CENTER)
tree.column('Humidity', width=70, anchor=tk.CENTER)
tree.column('Precipitation', width=70, anchor=tk.CENTER)
scrollbar_2 = Scrollbar(elenco_my_sub_frame, orient=tk.VERTICAL)
tree.config(yscrollcommand=scrollbar_2.set)
scrollbar_2.config(command=tree.yview)
scrollbar_2.pack(side=tk.RIGHT, fill=tk.Y)
tree.pack(padx=5, pady=5)
button_back_2 = tk.Button(elenco_my_sub_frame, text="Indietro", command=back_menu_2)
button_back_2.pack(side=tk.LEFT, padx=(95, 5))
button_update = tk.Button(elenco_my_sub_frame, text="Modifica", command=update_items)
button_update.pack(side=tk.LEFT, padx=(5, 5))
button_delete = tk.Button(elenco_my_sub_frame, text="Elimina", command=delete_items)
button_delete.pack(side=tk.LEFT, padx=(5, 5))
# Frame update
update_frame = tk.Frame(root)
blk_label_update = tk.Label(update_frame, text=" ")
blk_label_update.pack()
button_update_name = tk.Button(update_frame, text="Cambia Username", command=switch_to_update_username)
button_update_name.pack()
blk_label_update_5 = tk.Label(update_frame, text=" ")
blk_label_update_5.pack()
button_update_email = tk.Button(update_frame, text="Cambia Email", command=switch_to_update_email)
button_update_email.pack()
blk_label_update_4 = tk.Label(update_frame, text=" ")
blk_label_update_4.pack()
button_update_password = tk.Button(update_frame, text="Cambia Password", command=switch_to_update_psw)
button_update_password.pack()
blk_label_update_3 = tk.Label(update_frame, text=" ")
blk_label_update_3.pack()
button_update_back = tk.Button(update_frame, text="Indietro", command=back_from_update_menu)
button_update_back.pack()
blk_label_update_2 = tk.Label(update_frame, text=" ")
blk_label_update_2.pack()
# frame update name
form_update_name = tk.Frame(root)
label_old = tk.Label(form_update_name, text="Username corrente")
entry_old = tk.Entry(form_update_name)
entry_old.config(state='readonly')
label_new = tk.Label(form_update_name, text="Nuovo username")
entry_new = Entry(form_update_name)
label_pass = tk.Label(form_update_name, text="password")
entry_pass = Entry(form_update_name, show="*")
button_confirm = tk.Button(form_update_name, text="Conferma",
                           command=lambda: update(entry_pass.get(), entry_new.get(), "username"))
label_old.pack()
entry_old.pack()
label_new.pack()
entry_new.pack()
label_pass.pack()
entry_pass.pack()
blk = tk.Label(form_update_name, text=" ")
blk.pack()
button_confirm.pack(side=tk.LEFT, padx=(5, 5))
button_update_back = tk.Button(form_update_name, text="Indietro", command=back_to_menu_from_username)
button_update_back.pack(side=tk.LEFT, padx=(5, 5))
# frame update email
form_update_email = tk.Frame(root)
label_old_email = tk.Label(form_update_email, text="Email corrente")
entry_old_email = tk.Entry(form_update_email)
entry_old_email.config(state='readonly')
label_new_email = tk.Label(form_update_email, text="Nuovo Email")
entry_new_email = Entry(form_update_email)
label_pass_email = tk.Label(form_update_email, text="password")
entry_pass_email = Entry(form_update_email, show="*")
button_confirm = tk.Button(form_update_email, text="Conferma",
                           command=lambda: update(entry_pass_email.get(), entry_new_email.get(), "email"))
label_old_email.pack()
entry_old_email.pack()
label_new_email.pack()
entry_new_email.pack()
label_pass_email.pack()
entry_pass_email.pack()
blk_email = tk.Label(form_update_email, text=" ")
blk_email.pack()
button_confirm.pack(side=tk.LEFT, padx=(5, 5))
button_update_back = tk.Button(form_update_email, text="Indietro", command=back_to_menu_from_email)
button_update_back.pack(side=tk.LEFT, padx=(5, 5))
# form update password
form_update_psw = tk.Frame(root)
label_psw = tk.Label(form_update_psw, text="Password corrente")
entry_psw = Entry(form_update_psw, show="*")
label_new_psw = tk.Label(form_update_psw,  text="Nuova Password")
entry_new_psw = Entry(form_update_psw, show="*")
button_confirm = tk.Button(form_update_psw, text="Conferma", command=lambda: update(entry_psw.get(), entry_new_psw.get(), "password"))
label_psw.pack()
entry_psw.pack()
label_new_psw.pack()
entry_new_psw.pack()
blk_psw = tk.Label(form_update_psw, text=" ")
blk_psw.pack()
button_confirm.pack(side=tk.LEFT, padx=(5, 5))
button_update_back = tk.Button(form_update_psw, text="Indietro", command=back_to_menu_from_psw)
button_update_back.pack(side=tk.LEFT, padx=(5, 5))
# Imposta le dimensioni desiderate per la finestra
larghezza_finestra = 200
altezza_finestra = 200
schermo_larghezza = root.winfo_screenwidth()
schermo_altezza = root.winfo_screenheight()
x = (schermo_larghezza - larghezza_finestra) // 2
y = (schermo_altezza - altezza_finestra) // 2
root.resizable(False, False)
root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")
root.mainloop()
