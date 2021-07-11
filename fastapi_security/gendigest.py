"""Generate digest for basic_auth_with_digest credentials.

Takes an instance of FastAPISecurity that has basic_auth_with_digest configured
(even if with empty credential list), prompts for password and generates a
digest that can be appended to that instance's list of credentials.

Example:

$ python -m fastapi_security.gendigest fastapi_security.gendigest:obj
Password:
Confirm password:
0jFS-cNapwQf_lpyULF7_hEelbl_zreNVHbxqKwKIFmPRQ09bYTEDQLrr_UEWZc9fdYFiU5F3il3rovJQ_UEpg==

"""

import argparse
import importlib
import sys
import textwrap
from getpass import getpass
from types import ModuleType
from typing import Union

from fastapi_security import FastAPISecurity


def _wrap_paragraphs(s):
    paragraphs = s.strip().split('\n\n')
    wrapped_paragraphs = [
        '\n'.join(textwrap.wrap(paragraph)) for paragraph in paragraphs
    ]
    return '\n\n'.join(wrapped_paragraphs)


def import_from_string(import_str: Union[ModuleType, str]) -> ModuleType:
    """import_from_string: part of uvicorn codebase

    Copyright © 2017-present, Encode OSS Ltd. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

    Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
    """
    if not isinstance(import_str, str):
        return import_str

    module_str, _, attrs_str = import_str.partition(":")
    if not module_str or not attrs_str:
        message = (
            'Import string "{import_str}" must be in format "<module>:<attribute>".'
        )
        raise ValueError(message.format(import_str=import_str))

    try:
        module = importlib.import_module(module_str)
    except ImportError as exc:
        if exc.name != module_str:
            raise exc from None
        message = 'Could not import module "{module_str}".'
        raise ValueError(message.format(module_str=module_str))

    instance = module
    try:
        for attr_str in attrs_str.split("."):
            instance = getattr(instance, attr_str)
    except AttributeError:
        message = 'Attribute "{attrs_str}" not found in module "{module_str}".'
        raise ValueError(
            message.format(attrs_str=attrs_str, module_str=module_str)
        )

    return instance


parser = argparse.ArgumentParser(
    description=_wrap_paragraphs(__doc__),
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument('fastapi_security_obj')


obj = FastAPISecurity()
obj.init_basic_auth_with_digest('salt123', [])


def main():
    args = parser.parse_args()

    fastapi_security_obj = import_from_string(args.fastapi_security_obj)
    if callable(fastapi_security_obj):
        instance = fastapi_security_obj()
    elif isinstance(fastapi_security_obj, FastAPISecurity):
        instance = fastapi_security_obj
    else:
        print("Cannot generate digest: ", args.fastapi_security_obj,
              "must point to a FastAPISecurity object or a function returning one",
              file=sys.error)
        sys.exit(1)

    password = getpass(prompt='Password: ')
    password_confirmation = getpass(prompt='Confirm password: ')

    if password != password_confirmation:
        print("Cannot generate digest: passwords don't match", file=sys.stderr)
        sys.exit(1)

    print(instance.basic_auth_with_digest.generate_digest(password))


if __name__ == '__main__':
    main()
