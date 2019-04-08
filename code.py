from PIL import Image
import binascii
import optparse
from Crypto.Cipher import AES
import base64
import getpass
import webcolors


def rgb2hex(r, g, b):
	return webcolors.rgb_to_hex((r,g,b))


def hex2rgb(hexcode):
	return webcolors.hex_to_rgb(hexcode)


def str2bin(message):
	binary = bin(int(binascii.hexlify(message), 16))
	return binary[2:]


def bin2str(binary):
	message = binascii.unhexlify('%x' % (int('0b' + binary, 2)))
	return message


def encode(hexcode, digit):
	if hexcode[-1] in ('0', '1', '2', '3', '4', '5'):
		hexcode = hexcode[:-1] + digit
		return hexcode

	else:
		return None


def decode(hexcode):
	if hexcode[-1] in ('0', '1'):
		return hexcode[-1]

	else:
		return None


def hide(filename, message):
	img = Image.open(filename)
	binary = ''
	for msg in message:
		binary += str2bin(msg) + '1010101010101010'
	if img.mode in ('RGBA'):
		img = img.convert('RGBA')
		datas = img.getdata()
		newData = []
		digit = 0
		temp = ''

		for item in datas:
			if digit < len(binary):
				newpix = encode(rgb2hex(item[0], item[1], item[2]), binary[digit])
				if newpix is None:
					newData.append(item)
				else:
					r, g, b = hex2rgb(newpix)
					newData.append((r, g, b, 255))
					digit += 1
			else:
				newData.append(item)

		img.putdata(newData)
		img.save('1'+filename, "PNG")
		return "Completed!"

	return "Incorrect Image Mode, Couldn't Hide"


def retr(filename):
	img = Image.open('1'+filename)
	binary = ''
	str_output = []
	if img.mode in ('RGBA'):
		img = img.convert('RGBA')
		datas = img.getdata()
		for item in datas:
			digit = decode(rgb2hex(item[0], item[1], item[2]))
			if digit == None:
				pass

			else:
				binary = binary + digit
				if binary[-16:] == '1010101010101010':

					str_output.append(base64.b64decode(bin2str(binary[:-16])))
					binary = ''

		return str_output

	return "Incorrect Image Mode, Couldn't Retrieve"


def main():
	parser = optparse.OptionParser('usage %prog -e/-d <target file>')

	parser.add_option('-e', dest='hide', type='string',
					  help='target picture path to hide text')

	parser.add_option('-d', dest='retr', type='string',
					  help='target picture path to retrieve text')

	(options, args) = parser.parse_args()
	if options.hide is not None:
		text = input("Enter a message to hide: ")
		password = getpass.getpass()
		# password = raw_input("Enter your password: ")
		cipher = AES.new(password.rjust(16), AES.MODE_ECB)
		encoded = []
		while(len(text)>0):
			print(len(text))
			if len(text)>16:
				block = text[:16]
				text = text[16:]
			else:
				block = text
				text = ""
			encoded.append(base64.b64encode(cipher.encrypt(block.rjust(32))))
		print(hide(options.hide, encoded))

	elif options.retr is not None:
		password = getpass.getpass()
		# password = raw_input("Enter your password: ")
		cipher = AES.new(password.rjust(16), AES.MODE_ECB)
		# decoded = cipher.decrypt(base64.b64decode(retr(options.retr)))
		str_out = retr(options.retr)
		decoded = ''
		for i in str_out:
			decoded += cipher.decrypt(i).decode('utf-8').strip()

		print("Success! Encrypted message is : ")
		print(decoded)

	else:
		print(parser.usage)
		exit(0)


if __name__ == '__main__':
	main()
