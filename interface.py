from tkinter import *
from skipjackfolder.skipjackclass import SkipJack
import random

window = Tk()
window.geometry('1200x500')
window.title('SkipJack')
name_label = Label(window, text='SkipJack encode/decode', bg='dark gray', font=('Times', 30, 'bold'))
name_label.pack(side=TOP)
window.config(background='Dark gray')

plain_text = StringVar()
plain_text.set('введите исходное сообщение')
cipher_text = StringVar()
cipher_text.set('тут будет зашифрованное сообщение')
cipher_text_input = StringVar()
cipher_text_input.set('введите зашифрованное сообщение')
decrypt_text = StringVar()
decrypt_text.set('тут будет расшифрованное сообщение')

sj = SkipJack()

# случайно генерируем ключ
KEY = []
for key_byte in range(10):
    KEY.append(random.randint(0, 255))


def encode():
    user_input = input_widget.get()
    current_plain_text = sj.convert_input_text(user_input)
    current_cipher_text = []
    for block in current_plain_text:
        cipher = sj.encrypt(block, KEY)
        current_cipher_text.append(cipher)

    human_plain = []
    human_cipher = []
    for word in range(len(current_plain_text)):
        p1 = (current_plain_text[word] >> 16 * 3) & 0xffff
        p2 = (current_plain_text[word] >> 16 * 2) & 0xffff
        p3 = (current_plain_text[word] >> 16 * 1) & 0xffff
        p4 = current_plain_text[word] & 0xffff
        plain = list(map(chr, [p1, p2, p3, p4]))
        human_plain.extend(plain)

        c1 = (current_cipher_text[word] >> 16 * 3) & 0xffff
        c2 = (current_cipher_text[word] >> 16 * 2) & 0xffff
        c3 = (current_cipher_text[word] >> 16 * 1) & 0xffff
        c4 = current_cipher_text[word] & 0xffff

        cipher = list(map(chr, [c1, c2, c3, c4]))
        human_cipher.extend(cipher)

    cipher_text.set(''.join(human_cipher))
    cipher_text_input.set(''.join(human_cipher))


def decode():
    user_input = input_ciphered_widget.get()
    current_cipher_text = sj.convert_input_text(user_input)
    current_decrypt_text = []
    for cipher in current_cipher_text:
        decrypt = sj.decrypt(cipher, KEY)
        current_decrypt_text.append(decrypt)

    human_cipher_input = []
    human_decrypt = []
    for word in range(len(current_cipher_text)):
        ci1 = (current_cipher_text[word] >> 16 * 3) & 0xffff
        ci2 = (current_cipher_text[word] >> 16 * 2) & 0xffff
        ci3 = (current_cipher_text[word] >> 16 * 1) & 0xffff
        ci4 = current_cipher_text[word] & 0xffff

        cipherinput = list(map(chr, [ci1, ci2, ci3, ci4]))
        human_cipher_input.extend(cipherinput)

        d1 = (current_decrypt_text[word] >> 16 * 3) & 0xffff
        d2 = (current_decrypt_text[word] >> 16 * 2) & 0xffff
        d3 = (current_decrypt_text[word] >> 16 * 1) & 0xffff
        d4 = current_decrypt_text[word] & 0xffff
        decrypt = list(map(chr, [d1, d2, d3, d4]))
        human_decrypt.extend(decrypt)

    # убираем пробелы с конца
    while human_decrypt[-1] == chr(0):
        human_decrypt.pop()

    decrypt_text.set(''.join(human_decrypt))


input_widget = Entry(window, font=('Counier New', 12, 'bold'), textvar=plain_text, width=200, bd=2, bg='white')
input_widget.pack()

ciphered_widget = Entry(window, font=('Counier New', 12, 'bold'), textvar=cipher_text, width=200, bd=2, bg='white')
ciphered_widget.pack()

input_ciphered_widget = Entry(window, font=('Counier New', 12, 'bold'), textvar=cipher_text_input, width=200, bd=2, bg='white')
input_ciphered_widget.pack()

decrypted_widget = Entry(window, font=('Counier New', 12, 'bold'), textvar=decrypt_text, width=200, bd=2, bg='white')
decrypted_widget.pack()

encode_button = Button(window, padx=15, pady=14, bd=4, bg='white', command=encode, text='закодировать', font=('Courier New', 16, 'bold'))
encode_button.place(x=10, y=250)

decode_button = Button(window, padx=15, pady=14, bd=4, bg='white', command=decode, text='раскодировать', font=('Courier New', 16, 'bold'))
decode_button.place(x=250, y=250)

window.mainloop()
