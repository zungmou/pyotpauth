# https://datatracker.ietf.org/doc/html/rfc6238

import base64
import binascii
import io
import os
import subprocess
import tempfile
from urllib.parse import parse_qs, quote, unquote, urlparse

import click
import google.protobuf.message
# https://github.com/lincolnloop/python-qrcode
# pip install qrcode[pil]
import qrcode

# First time using protobuf:
# pip install protobuf
from otpauth_migration_pb2 import Payload

OtpType = {
    'hotp': Payload.OTP_TYPE_HOTP,
    'totp': Payload.OTP_TYPE_TOTP
}

HELP = ('Encode a set of otpauth:// into migration format and display the QR code for Google Authenticator to scan and import.'
        '\n\nor'
        '\n\nDecode the content of the migration format exported from Google Authenticator into a set of otpauth://'
        '\n\nNote: The content to be encoded and decoded is provided in the form of file paths.')


@click.command(help=HELP)
@click.argument(
    'method',
    type=click.Choice(['encode', 'decode'], case_sensitive=False)
)
@click.argument(
    'file',
    type=click.Path(exists=True, file_okay=True, readable=True)
)
@click.option(
    '--box-size',
    type=click.IntRange(1, 10),
    default=3,
    help='The size of the QR code displayed after encoding'
)
def migration(method, file: str, box_size: int):
    if method == 'encode':
        payload = Payload()

        with open(file, mode='r') as fp:
            lines = fp.readlines()

        for line in lines:
            if line.isspace():
                continue

            line = line.strip()
            url_components = urlparse(line)
            query_strings = parse_qs(url_components.query)
            parameter = dict(
                secret=query_strings['secret'][0],
                name=unquote(url_components.path.split(':')[-1]),
                issuer=query_strings['issuer'][0],
                algorithm=Payload.ALGORITHM_SHA1,
                digits=Payload.DIGIT_COUNT_SIX,
                type=OtpType[url_components.hostname.lower()]
            )
            if len(parameter['secret']) % 8:
                parameter['secret'] += '=' * (8-len(parameter['secret']) % 8)
            parameter['secret'] = base64.b32decode(parameter['secret'], True)

            payload.otp_parameters.append(Payload.OtpParameters(**parameter))

        data = payload.SerializeToString()
        data = base64.b64encode(data)
        data = data.decode('ascii')
        data = quote(data)
        data = f'otpauth-migration://offline?data={data}'

        img = qrcode.make(data, box_size=box_size)

        with io.BytesIO() as output:
            img.convert("RGB").save(output, "BMP")

            fd, filename = tempfile.mkstemp()
            try:
                output.seek(0)
                output = output.read()
                os.write(fd, output)
                os.close(fd)
                subprocess.run(['mspaint', filename])
            finally:
                os.remove(filename)

    elif method == 'decode':
        with open(file, mode='r') as fp:
            try:
                data = fp.read()
                data = urlparse(data)
                data = data.query
                data = parse_qs(data)['data'][0]
                data = base64.b64decode(data)

                payload = Payload()
                data = payload.FromString(data)

                for item in data.otp_parameters:
                    print(f'otpauth://{Payload.OtpType.Name(item.type).lower()[-4:]}/{item.issuer}:{item.name}?secret={base64.b32encode(item.secret).decode("ascii")}&issuer={item.issuer}')

            except (KeyError, binascii.Error, google.protobuf.message.DecodeError):
                raise click.BadParameter("Unable to decode the file content, please make sure it is exported from Google Authenticator.")


if __name__ == '__main__':
    migration()
