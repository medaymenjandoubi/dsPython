from email import message
from enum import verify
from http import server
from lib2to3.pgen2.literals import evalString
from operator import truediv
import colorama
import cowsay
from getpass import getpass
import re
import hashlib

def email_exists(email):
    with open('SSIR.txt', 'r') as file:
        for line in file:
            parts = line.strip().split(':')
            if len(parts) >= 2 and email == parts[0]:
                return True
    return False



def introduire_email():
    global email
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    while True:
        email = input("Donnez votre email: ")
        if re.fullmatch(regex, email):
            if email_exists(email):
                print("Email already registered")
            else:
                return email
        else:
            print("Invalid email")


def generateDictionnary():
    import random
    import nltk
    from nltk.corpus import words

    nltk.download('words')
    mots_francais = words.words()
    dictionnaire_faux = random.sample(mots_francais, 2000)
    with open("dictionnaire.txt", "w", encoding="utf-8") as fichier:
        fichier.writelines('\n'.join(dictionnaire_faux))
    print("Dictionnaire généré avec succès.")

def attaque_par_dictionnaire(word):
    with open("dictionnaire.txt", "r", encoding="utf-8") as fichier:
        lignes = fichier.readlines()
    for ligne in lignes:
        mot_dictionnaire = ligne.strip() 
        if mot_dictionnaire == word:
            print(f"Mot trouvé : {word} est présent dans le dictionnaire.")
            break
    else:
        print(f"Mot non trouvé : {word} n'est pas présent dans le dictionnaire.")







def introduire_pwd():
    import string
    import getpass
    global p
    while True:
        p = getpass.getpass(prompt='Password: ', stream=None)
        if len(p) >= 8:
            if any(car in string.digits for car in p) :
                if any(car in string.ascii_uppercase for car in p):
                    if any(car in string.ascii_lowercase for car in p):
                        if any(car in string.punctuation for car in p):
                            p = hashlib.sha256(p.encode()).hexdigest()
                            return p
                        else:
                            print("Au moins un caractere special")
                    else:
                        print("Au minimum une lettre minuscule")
                else:
                    print("Au moins une lettre majuscule")
            else:
                print("Au moins un caractere numerique")
        else:
            print("Longueur minimale : 8")

def register():
    print(colorama.Fore.GREEN + 'Exercice 1')
    cowsay.fox("Enregistrement ")

    x = introduire_email()

    y = introduire_pwd()


    with open('SSIR.txt', 'a') as file:
        file.write(f"\n{x}:{y}")

def authenticate():
    from getpass import getpass
    while True:
        email = input("Enter your email: ")
        password = getpass("Enter your password: ")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open('SSIR.txt', 'r') as file:
            for line in file:
                parts = line.strip().split(':')
                print(parts[0],parts[1])
                if len(parts) == 2 and email == parts[0] and hashed_password == parts[1]:
                    print("Authentication successful. Welcome to the menu.")
                    authMenu()
                    return False
        print("Authentication failed. Please try again or register.")



def generer_paires_de_cles_RSA(nom_fichier, taille_cles=2048):
    from Crypto.PublicKey import RSA 
    cle_rsa = RSA.generate(2048) 
    cle_privee = cle_rsa.exportKey("PEM") 
    cle_publique = cle_rsa.publickey().exportKey("PEM")
    with open("cle_publique.txt", "wb") as fichier:
        fichier.write(cle_publique)
    with open("cle_prive.txt", "wb") as fichier :
        fichier.write(cle_privee)

    print(f"Paires de clés RSA générées et enregistrées dans {nom_fichier}.")

def chiffrer_message():
    from Crypto.Cipher import PKCS1_OAEP 
    from Crypto.PublicKey import RSA 
    try:
        message = input("Entrez le message à chiffrer : ")
        message_bytes = message.encode('utf-8')
        cle = RSA.import_key(open('cle_publique.txt').read()) 
        cipher = PKCS1_OAEP.new(cle) 
        ciphertext = cipher.encrypt(message_bytes) 
        print(ciphertext)
        if ciphertext:
            print("Message chiffré avec succès :") 
        return ciphertext
    except Exception as e:
        print(f"Erreur lors du chiffrement du message : {e}")
        return None
def signer_message():
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    cle = RSA.import_key(open('cle_prive.txt').read()) 
    message = input("Entrez le message a signer :")
    message_bytes = message.encode('utf-8')
    h = SHA256.new(message_bytes)
    signature = pkcs1_15.new(cle).sign(h)
    if signature:
        print("Signature du message:")
        print(signature)
        return message_bytes,signature

def verifier_signature(message_bytes,signature):
        from Crypto.Signature import pkcs1_15
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        cle = RSA.import_key(open('cle_publique.txt').read())
        h = SHA256.new(message_bytes)
        try:
            pkcs1_15.new(cle).verify(h, signature)
            print("La signature est valide.")
        except (ValueError, TypeError):
            print("La signature n'est pas valide.")

def dechiffrer_message(ciphertext):
    from Crypto.Cipher import PKCS1_OAEP 
    from Crypto.PublicKey import RSA 
    cle = RSA.import_key(open('cle_prive.txt').read()) 
    cipher = PKCS1_OAEP.new(cle) 
    message_dechiffre = cipher.decrypt(ciphertext) 
    if message_dechiffre:
        print(message_dechiffre)
        print('message dechifré avec success')

def generer_paires_de_cles_RSA(nom_fichier, taille_cles=2048):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=taille_cles
    )

    cle_privee_serialisee = cle_privee.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    cle_publique_serialisee = cle_privee.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(nom_fichier, "wb") as fichier:
        fichier.write(cle_privee_serialisee)
        fichier.write(cle_publique_serialisee)

    print(f"Paires de clés RSA générées et enregistrées dans {nom_fichier}.")
    return cle_privee

def generer_certificat_autosigne(cle_privee, nom_fichier_certificat):
    import datetime
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes


    cle_publique = cle_privee.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mon Entreprise"),
        x509.NameAttribute(NameOID.COMMON_NAME, "www.monentreprise.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        cle_publique
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("www.monentreprise.com")]),
        critical=False,
    ).sign(cle_privee, hashes.SHA256(), default_backend())

    with open(nom_fichier_certificat, "wb") as fichier:
        fichier.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificat autosigné généré et enregistré dans {nom_fichier_certificat}.")
def chiffrer_message_par_certificat(message, certificat):
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import padding
    # Charger le certificat
    with open(certificat, "rb") as fichier_certificat:
        cert = x509.load_pem_x509_certificate(fichier_certificat.read(), default_backend())

    # Chiffrer le message
    message_chiffre = cert.public_key().encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if message_chiffre:
        print("message chiffré avec succés")
    return message_chiffre
def authMenu():
    import bcrypt
    from cryptography.hazmat.primitives import serialization
    print("Welcome to the menu:")
    while True:
        print(" A-Hash a word")
        print(" B-Chiffrement RSA")
        print(" C-Certificat RSA")
        choice = input("Choose an option (A/B/C): ").upper()
        if choice == 'A':
            from getpass import getpass
            word=getpass("Insert a word to hash")
            if word :
                while True:
                        print("1- Hache le mot par sha256 ") 
                        print("2- Hache le mot en generant un salt (bcrypt)")
                        print("3- Attaquer par dictionnaire le mot insere.") 
                        print("4- Revenir au menu principal ")
                        choiceSubMenu = input('veuillez choisir un chiffre entre 1 et 4 : ')
                        if (choiceSubMenu == '1'):
                            print(hashlib.sha256(word.encode()).hexdigest())
                            break
                        elif (choiceSubMenu == '2'):
                            s= bcrypt.gensalt()
                            result_s=bcrypt.hashpw(word.encode(),s)
                            print("the word was successfully hashed with salt bcrypt Congratulations")
                            break
                        elif (choiceSubMenu == '3'):
                            generateDictionnary()
                            attaque_par_dictionnaire(word)
                            break
                        elif (choiceSubMenu == "4"):
                                    print("Au revoir !")
                                    break
                        else :
                            print("Option invalide. Veuillez sélectionner une option valide.")
              
        elif choice == 'B':
            print("Welcome to the RSA Menu")
            while True:
                            print("A- generate Keys ") 
                            print("B- chiffrer with RSA")
                            print("C- dechiffrer avec RSA.") 
                            print("D- Signer un message ")
                            print("E- Verifier la signature ")
                            print("F- Quitter ")
                            choiceSubMenu = input('veuillez choisir un chiffre entre 1 et 4 : ')
                            if (choiceSubMenu == 'A'):
                                text = "cle_RSA.txt"
                                generer_paires_de_cles_RSA(text)
                                break
                            elif (choiceSubMenu == 'B'):
                                ciphertext= chiffrer_message()
                                break
                            elif (choiceSubMenu == 'C'):
                                dechiffrer_message(ciphertext)
                                break
                            elif (choiceSubMenu == "D"):
                                message_bytes,signature = signer_message()
                                # print(f"{message_bytes}, ceci est le message_bytes")
                                # print(f"{signature} celle ci est la signature")
                            elif ( choiceSubMenu == "E"):
                                verifier_signature(message_bytes,signature)
                                break
                            elif (choiceSubMenu == "F"):
                                print("Au revoir !")
                                break
                            else :
                                print("Option invalide. Veuillez sélectionner une option valide.")
                        

        elif choice == 'C':
            print("Welcome to the RSA Certificate Menu")
            while True:
                            print("A- generate Keys with certificate") 
                            print("B- generer un Certificat autosigné ")
                            print("C- chiffré un message a l'aide de ce certificat")
                            choiceSubMenu = input('veuillez choisir un chiffre entre A et C : ').upper()
                            if (choiceSubMenu == 'A'):
                                text = "cle_certificat_RSA.txt"
                                cle_privee=generer_paires_de_cles_RSA(text)
                            elif (choiceSubMenu == "B"):
                                generer_certificat_autosigne(cle_privee, "certificat_autosigne.txt")
                            elif (choiceSubMenu == "C"):
                                message_a_chiffrer = input("Veuillez entrer le message a chiffrer svp : ")
                                chiffrer_message_par_certificat(message_a_chiffrer,"certificat_autosigne.txt")
                            elif (choiceSubMenu == "F"):
                                print("Au revoir !")
                                break
                            else :
                                print("Option invalide. Veuillez sélectionner une option valide.")




        else:
            print("Invalid choice. Please select 1, 2, or 3.")



def main():
    print(colorama.Fore.GREEN + 'Exercice 1')
    cowsay.fox("Enregistrement ")
    print("1-Register")
    print("2-Authenticate")
    while True:
        choice = input("Choose an option (1/2): ")
        
        if choice == '1':
            register()
        elif choice == '2':
            authenticate()
            # You can add your menu here after successful authentication
        else:
            print("Invalid choice. Please select 1 or 2.")

if __name__ == "__main__":
    main()
