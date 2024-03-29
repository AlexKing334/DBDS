Se il progetto viene eseguito dopo il 7 febbraio si prega di registrare un account di prova presso
https://www.meteomatics.com/en/sign-up-weather-api-test-account "cliccando su sign up now"
una volta ottenuti i dati tramite email, aprire tramite blocco note il docker file dentro la cartella
Progetto/producer e sostituire le vecchie credenziali con le nuove nella sezione dedicata alle variabili
di ambiente.

Installare docker desktop
Aprire un terminale nella cartella progetto
Usare il comando: docker compose up -d
una volta create le immagini, si avvieranno in automatico.
Se si vuole eseguire in ambiente k8s:
Abilitare K8s da docker desktop, cliccando su impostazioni e poi k8s.
Appena in basso a destra diventa verda il logo k8s sarà possibile eseguire il prossimo comando, ma prima
andare nella sezione container ed eliminare tutti i container per evitare spreco di risorse.
Aprire un terminale nella cartella k8s_project/k8s e utilizzare il comando: kubectl apply -f .

Se il progetto viene eseguito dopo il 9 febbraio si prega di registrare un account di prova presso
https://www.meteomatics.com/en/sign-up-weather-api-test-account "cliccando su sign up now"
una volta ottenuti i dati tramite email, aprire tramite blocco note il docker file dentro la cartella
Progetto/producer e sostituire le vecchie credenziali con le nuove nella sezione dedicata alle variabili
di ambiente.
