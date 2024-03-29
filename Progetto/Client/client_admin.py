import base64
import re
import json
from io import BytesIO
import requests
import tkinter as tk
from OpenSSL import crypto
from email.utils import parseaddr
import tkinter.ttk as ttk, tkcalendar
from tkinter import messagebox, Scrollbar, Entry
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib import pyplot as plt
from urllib3.exceptions import InsecureRequestWarning


def show_image(base64_string):
    try:
        img_data = base64.b64decode(base64_string)
        img_buffer = BytesIO(img_data)
        img = plt.imread(img_buffer)
        root = tk.Tk()
        root.title("Image Viewer")
        fig, ax = plt.subplots()
        ax.imshow(img)
        ax.axis('off')
        canvas = FigureCanvasTkAgg(fig, master=root)
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=1)
        toolbar = NavigationToolbar2Tk(canvas, root)
        toolbar.update()
        canvas_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        def on_close():
            root.destroy()

        close_button = tk.Button(root, text="Close", command=on_close)
        close_button.pack(side=tk.BOTTOM)
        root.mainloop()

    except Exception as e:
        print(f"Errore durante la visualizzazione dell'immagine: {e}")


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


user = User("username", "token", "prova.prova@prova.prova")


def generate_self_signed_cert(cert_file, key_, days_valid=365):
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "ClientAdmin"
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
        url = "https://localhost:5000/login_admin"
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


def mostra_elenco_sla_violation(sla):
    violation_panel_frame.pack_forget()
    elenco_sla_violation.pack()
    for i, el in enumerate(sla):
        data = (el['name'], el['value'], el['timestamp'])
        tree_.insert('', tk.END, iid=f"{i}", text=el['id'], values=data)
    for colonna in tree_["columns"]:
        tree_.column(colonna, stretch=True)
    altezza_widget = min(20, 10)
    tree_["height"] = altezza_widget
    larghezza_widget = 700
    altezza_widget = 300
    x_2 = (schermo_larghezza - larghezza_widget) // 2
    y_2 = (schermo_altezza - altezza_widget) // 2
    num_sla = len(sla)
    if num_sla > 7:
        scrollbar_2.pack(side=tk.RIGHT, fill=tk.Y)
    else:
        scrollbar_2.pack_forget()
    root.geometry(f"{larghezza_widget}x{altezza_widget}+{x_2}+{y_2}")


def get_violation(type_req, value):
    try:
        url = "https://localhost:7000/get_violation"
        payload = {"type_req": type_req, "value": value, 'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            mostra_elenco_sla_violation(result['sla'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            messagebox.showerror("Errore", result['message'])
    except Exception as err:
        print(err)
        messagebox.showerror("Errore", "Slamanager non raggiungibile")


def get_prediction(dati):
    try:
        name, threshold = dati.split("|")
        url = "https://localhost:5555/prediction"
        payload = {"name": name, "threshold": threshold, 'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            messagebox.showinfo("Probabilità", result["message"])
            show_image(result["plot"])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            messagebox.showerror("Errore", result['message'])
    except Exception as err:
        print(err)
        messagebox.showerror("Errore", "Slamanager non raggiungibile")


def get_sla_rules():
    try:
        url = "https://localhost:7000/get_sla_rules"
        payload = {'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            mostra_elenco_sla_rules(result['sla'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            lista = []
            mostra_elenco_sla_rules(lista)
    except Exception as err:
        print(err)
        messagebox.showerror("Errore", "Slamanager non raggiungibile")


def get_metrics_list():
    try:
        url = "https://localhost:7000/get_sla_rules"
        payload = {'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.get(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            mostra_elenco_metrics(result['sla'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            lista = []
            mostra_elenco_metrics(lista)
    except Exception as err:
        print(err)
        messagebox.showerror("Errore", "Slamanager non raggiungibile")


def mostra_menu():
    login_frame.pack_forget()  # Nasconde il frame di login
    menu_frame.pack()  # Mostra il frame del menu


def reverse_mostra_menu():
    menu_frame.pack_forget()  # Nasconde il frame di login
    login_frame.pack()  # Mostra il frame del menu


def force_logout():
    # User = None
    menu_frame.pack_forget()
    elenco_sla_violation.pack_forget()
    elenco_my_sub_frame.pack_forget()
    violation_panel_frame.pack_forget()

    login_frame.pack()


def back_menu_6(prediction_frame):
    prediction_frame.destroy()
    menu_frame.pack()
    root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")


def back_menu_3():
    violation_panel_frame.pack_forget()
    menu_frame.pack()
    root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")


def back_menu_5():
    elenco_sla_violation.pack_forget()  # Nasconde il frame di login
    tree_.delete(*tree_.get_children())
    back_menu_4()
    violation_panel_frame.pack()
    root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")


def back_menu_2():
    elenco_my_sub_frame.pack_forget()  # Nasconde il frame di login
    menu_frame.pack()  # Mostra il frame del menu
    tree.delete(*tree.get_children())
    root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")


def update_items():
    selected_items = tree.selection()
    if not selected_items:
        return
    for item in selected_items:
        name = tree.set(item, 'name')
        threshold = tree.set(item, 'threshold')
        setActive = tree.set(item, 'isActive')
        data = (name, threshold, setActive)
        new_form(data)


def mostra_elenco_sla():
    menu_frame.pack_forget()  # Nasconde il frame del menu
    violation_panel_frame.pack()  # Mostra il frame dell'elenco dei topic


def mostra_elenco_sla_rules(topics):
    menu_frame.pack_forget()
    elenco_my_sub_frame.pack()
    for i, el in enumerate(topics):
        data = (el['name'], el['threshold'], el['isActive'])
        tree.insert('', tk.END, iid=f"{i}", text=el['id'], values=data)
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


def mostra_elenco_metrics(metrics):
    # Frame sla violation menu
    prediction_frame = tk.Frame(root)
    blk_label_pf_3 = tk.Label(prediction_frame, text=" ")
    active_var_ = tk.StringVar()
    label_mode_prediction = tk.Label(prediction_frame, text="Metriche:")
    button_back_prediction_frame = tk.Button(prediction_frame, text="Indietro", command=lambda: back_menu_6(prediction_frame))
    menu_frame.pack_forget()
    values = [f"{el['name']}|{el['threshold']}" for el in metrics]
    sla_selection_list = ttk.Combobox(prediction_frame, values=values, textvariable=active_var_)
    prediction_frame.pack()
    label_mode_prediction.pack()
    sla_selection_list.pack()
    button_prediction_confirm = tk.Button(prediction_frame, text="Conferma",
                                          command=lambda: get_prediction(sla_selection_list.get()))
    blk_label_pf_3.pack()
    button_prediction_confirm.pack(side=tk.LEFT, padx=(5, 5), pady=(10, 0))
    button_back_prediction_frame.pack(side=tk.LEFT, padx=(5, 5), pady=(10, 0))


def update_sla(nome, threshold, is_active, window):
    try:
        url = "https://localhost:7000/update_sla"
        payload = {'name': nome, 'threshold': threshold, 'isActive': str(is_active), 'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.put(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            if tree.get_children():
                tree.delete(*tree.get_children())
                get_sla_rules()
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
        url = "https://localhost:7000/update"
        payload = {'val_new': val_new, 'password': password, 'update': data, 'token': user.getToken()}
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.put(url, json=payload, cert=(cert_, key_file), verify=False)
        result = response.json()
        if result['success']:
            if data == "email":
                user.setEmail(val_new)
            elif data == "username":
                user.setUsername(val_new)
            user.setToken(result['token'])
            messagebox.showinfo("Update", result['message'])
        else:
            if "Token" in result['message']:
                force_logout()
                messagebox.showinfo("Logout", "Token scaduto, effettua il login")
                return
            messagebox.showerror("Update", result['message'])
    except Exception as err:
        print(err)


def reset_entry_value(entry, check_var):
    if check_var.get() == 1:  # Se la casella di controllo è selezionata
        entry.delete(0, tk.END)  # Cancella il valore attuale
        entry.config(state='disabled')  # Rendi il campo non modificabile
    else:
        entry.config(state='normal')  # Rendi il campo modificabile


def new_form(data):
    form_window = tk.Toplevel(root)
    form_window.title("SLA MANAGER")
    form_window.geometry(f"{300}x{200}+{x}+{y}")  # Aumentato l'altezza per adattarsi ai nuovi campi
    label_nome = tk.Label(form_window, text="Nome:")
    entry_nome = Entry(form_window)
    if isinstance(data, tuple):
        entry_nome.insert(0, data[0])
    else:
        entry_nome.insert(0, data)
    entry_nome.config(state='readonly')  # Rendi il campo non modificabile
    label_threshold = tk.Label(form_window, text="Threshold:")
    entry_threshold = Entry(form_window)
    if isinstance(data, tuple):
        entry_threshold.insert(0, data[1])
    label_active = tk.Label(form_window, text="Attivo:")
    # Utilizzo di ttk.Combobox per creare un menu a tendina
    entry_active = ttk.Combobox(form_window, values=["True", "False"])
    if isinstance(data, tuple):
        if data[2] == "1":
            entry_active.set("True")  # Imposta il valore iniziale
        else:
            entry_active.set("False")  # Imposta il valore iniziale
    button_conf = tk.Button(form_window, text="Conferma", command=lambda: update_sla(entry_nome.get(), entry_threshold.get(), entry_active.get(), form_window))
    label_nome.grid(row=0, column=0, sticky=tk.E)
    entry_nome.grid(row=0, column=1, sticky=tk.W)

    label_threshold.grid(row=1, column=0, sticky=tk.E)
    entry_threshold.grid(row=1, column=1, sticky=tk.W)

    label_active.grid(row=2, column=0, sticky=tk.E)
    entry_active.grid(row=2, column=1, sticky=tk.W)

    button_conf.grid(row=5, column=1, pady=10)
    blk_ = tk.Label(form_window, text=" ")
    blk_.grid(row=6, column=0, columnspan=3)


root = tk.Tk()
root.title("Panel Admin")
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
button_login.pack(side=tk.LEFT, padx=(38, 0))
login_frame.pack()
# Frame per il menu
menu_frame = tk.Frame(root)
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_subscription = tk.Button(menu_frame, text="SLA Violation List", command=mostra_elenco_sla)
button_subscription.pack()
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_subscription_active = tk.Button(menu_frame, text="SLA Rules", command=get_sla_rules)
button_subscription_active.pack()
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_prediction = tk.Button(menu_frame, text="Prediction", command=get_metrics_list)
button_prediction.pack()
blk_label = tk.Label(menu_frame, text=" ")
blk_label.pack()
button_logout = tk.Button(menu_frame, text="Logout", command=logout)
button_logout.pack()

# Elenco SLA violation table frame
elenco_sla_violation = tk.Frame(root)
tree_ = ttk.Treeview(elenco_sla_violation, columns=("name", "value", "timestamp"), height=20)
tree_.heading('#0', text='id', anchor=tk.CENTER)
tree_.heading('name', text='name', anchor=tk.CENTER)
tree_.heading('value', text='value', anchor=tk.CENTER)
tree_.heading('timestamp', text='timestamp', anchor=tk.CENTER)
# Allo stesso modo per le colonne
tree_.column('#0', width=100, anchor=tk.CENTER)
tree_.column('name', width=100, anchor=tk.CENTER)
tree_.column('value', width=100, anchor=tk.CENTER)
tree_.column('timestamp', width=200, anchor=tk.CENTER)
scrollbar_2_ = Scrollbar(elenco_sla_violation, orient=tk.VERTICAL)
tree_.config(yscrollcommand=scrollbar_2_.set)
scrollbar_2_.config(command=tree_.yview)
scrollbar_2_.pack(side=tk.RIGHT, fill=tk.Y)
tree_.pack(padx=5, pady=5)
button_back_2_ = tk.Button(elenco_sla_violation, text="Indietro", command=back_menu_5)
button_back_2_.pack(side=tk.LEFT, padx=(230, 5))

# tabella per l'elenco SLA RULES
elenco_my_sub_frame = tk.Frame(root)
tree = ttk.Treeview(elenco_my_sub_frame, columns=("name", "threshold", "isActive"), height=20)
tree.heading('#0', text='id', anchor=tk.CENTER)
tree.heading('name', text='name', anchor=tk.CENTER)
tree.heading('threshold', text='threshold', anchor=tk.CENTER)
tree.heading('isActive', text='isActive', anchor=tk.CENTER)
# Allo stesso modo per le colonne
tree.column('#0', width=50, anchor=tk.CENTER)
tree.column('name', width=150, anchor=tk.CENTER)
tree.column('threshold', width=70, anchor=tk.CENTER)
tree.column('isActive', width=50, anchor=tk.CENTER)
scrollbar_2 = Scrollbar(elenco_my_sub_frame, orient=tk.VERTICAL)
tree.config(yscrollcommand=scrollbar_2.set)
scrollbar_2.config(command=tree.yview)
scrollbar_2.pack(side=tk.RIGHT, fill=tk.Y)
tree.pack(padx=5, pady=5)
button_back_2 = tk.Button(elenco_my_sub_frame, text="Indietro", command=back_menu_2)
button_back_2.pack(side=tk.LEFT, padx=(100, 5))
button_update = tk.Button(elenco_my_sub_frame, text="Modifica", command=update_items)
button_update.pack(side=tk.LEFT, padx=(5, 5))


def forget_sla_violation_menu():
    label_date_from.pack_forget()
    entry_date_from.pack_forget()
    label_date_to.pack_forget()
    entry_date_to.pack_forget()
    label_value.pack_forget()
    entry_value.pack_forget()
    blk_label_vpf_1.forget()
    blk_label_vpf_2.forget()
    blk_label_vpf_3.forget()
    blk_label_vpf_4.forget()
    button_update_name_2_0.pack_forget()
    button_update_name_2_1.pack_forget()
    button_update_name_2_2.pack_forget()
    button_back_violation_frame.forget()


def on_active_change(*args):
    selected_option = active_var.get()
    forget_sla_violation_menu()
    if selected_option == "fromDataToCurrent":
        label_date_from.pack()
        entry_date_from.pack()
        blk_label_vpf_1.pack()
        button_update_name_2_1.pack(side=tk.LEFT, padx=(5, 5))
    elif selected_option == "fromDataToData":
        label_date_from.pack()
        entry_date_from.pack()
        label_date_to.pack()
        entry_date_to.pack()
        blk_label_vpf_1.pack()
        button_update_name_2_2.pack(side=tk.LEFT, padx=(5, 5))
    else:
        label_value.pack()
        entry_value.pack()
        blk_label_vpf_1.pack()
        button_update_name_2_0.pack(side=tk.LEFT, padx=(5, 5))
    button_back_violation_frame.pack(side=tk.LEFT, padx=(5, 5))


def back_menu_4():
    forget_sla_violation_menu()
    label_mode.pack()
    entry_mode.pack()
    blk_label_vpf_1.pack()
    button_back_violation_frame.pack()


# Frame sla violation menu
violation_panel_frame = tk.Frame(root)
blk_label_vpf_1 = tk.Label(violation_panel_frame, text=" ")
blk_label_vpf_2 = tk.Label(violation_panel_frame, text=" ")
blk_label_vpf_3 = tk.Label(violation_panel_frame, text=" ")
blk_label_vpf_4 = tk.Label(violation_panel_frame, text=" ")
active_var = tk.StringVar()
label_mode = tk.Label(violation_panel_frame, text="Attivo:")
entry_mode = ttk.Combobox(violation_panel_frame, values=["hours", "days", "fromDataToCurrent", "fromDataToData"], textvariable=active_var)
label_mode.pack()
entry_mode.pack()
button_back_violation_frame = tk.Button(violation_panel_frame, text="Indietro", command=back_menu_3)
blk_label_vpf_1.pack()
button_back_violation_frame.pack()
entry_mode.bind("<<ComboboxSelected>>", on_active_change)
label_value = tk.Label(violation_panel_frame, text="value:")
entry_value = tk.Entry(violation_panel_frame)
label_date_from = tk.Label(violation_panel_frame, text="from:")
entry_date_from = tkcalendar.DateEntry(violation_panel_frame, date_pattern='yyyy-mm-dd')
label_date_to = tk.Label(violation_panel_frame, text="to:")
entry_date_to = tkcalendar.DateEntry(violation_panel_frame, date_pattern='yyyy-mm-dd')
button_update_name_2_0 = tk.Button(violation_panel_frame, text="Conferma",  command=lambda: get_violation(entry_mode.get(), entry_value.get()))
button_update_name_2_1 = tk.Button(violation_panel_frame, text="Conferma",  command=lambda: get_violation(entry_mode.get(), entry_date_from.get()))
button_update_name_2_2 = tk.Button(violation_panel_frame, text="Conferma",  command=lambda: get_violation(entry_mode.get(), {'from': entry_date_from.get(), 'to': entry_date_to.get()}))

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
