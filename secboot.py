#!/usr/bin/python3
import os
import re
import sys
import abc
import time
import shutil
import logging
import pexpect
import argparse
import typing as t
import pathlib as pl
from enum import Enum
import unittest as ut
import tempfile as tempf
import dataclasses as dc

logging.basicConfig(format='%(asctime)s %(levelname)s %(funcName)s:%(lineno)d: %(message)s')

# Exit on critical log
class ShutdownHandler(logging.Handler):
    def emit(self, record):
        print(record, file=sys.stderr)
        logging.shutdown()
        sys.exit(1)
logger = logging.getLogger()
logger.addHandler(ShutdownHandler(level=logging.CRITICAL))



# ==============================================================================================================
# ==============================================================================================================
# Common

def safe_move(dry_run: bool, src: pl.Path, dst: pl.Path) -> None: # Not using exceptions for error handling:
    logger.debug(f'{"NOT " if dry_run else ""}Moving {src} to {dst}')
    if dry_run:
        return
    try:
        shutil.move(src, dst)
    except:
        logger.critical(f'Failed to move {src} to {dst}: {sys.exc_info()[0]}')


def safe_copy(dry_run: bool, src: pl.Path, dst: pl.Path) -> None: # Not using exceptions for error handling:
    logger.debug(f'{"NOT " if dry_run else ""}Copying {src} to {dst}')
    if dry_run:
        return
    try:
        shutil.copy(src, dst)
    except:
        logger.critical(f'Failed to copy {src} to {dst}: {sys.exc_info()[0]}')


def safe_rm(dry_run: bool, path: pl.Path) -> None: # Not using exceptions for error handling:
    logger.debug(f'{"NOT " if dry_run else ""}Removing {path}')
    if dry_run:
        return
    try:
        import contextlib
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)
    except:
        logger.critical(f'Failed to remove {path}: {sys.exc_info()[0]}')


def safe_rm_dir(dry_run: bool, path: pl.Path) -> None:
    logger.debug(f'{"NOT " if dry_run else ""}Removing {path}')
    if dry_run:
        return
    try:
        shutil.rmtree(path)
    except:
        logger.critical(f'Failed to remove {path}: {sys.exc_info()[0]}')


@dc.dataclass
class ExecRes:
    out: str = ""
    ret: int = 0
    def is_ok(self) -> bool:
        return self.ret == 0
    def is_err(self) -> bool:
        return not self.is_ok()

def exec(dry_run: bool, command: str, echo_output: t.Union[bool, None] = None, root_is_required = False) -> ExecRes:
    if echo_output == None:
        echo_output=logger.level <= logging.DEBUG
    if root_is_required and os.geteuid() != 0:
        command = "sudo " + command
    if echo_output:
        logger.info(f'{"NOT " if dry_run else ""}executing: {command}')
    else:
        logger.debug(f'{"NOT " if dry_run else ""}executing: {command}')
    if dry_run:
        return ExecRes()

    # Curses try #2: https://stackoverflow.com/questions/24946988/using-python-subprocess-call-to-launch-an-ncurses-process
    child = None

    # Unfortunately pexpect.spawn throws exceptions, let's fix it:
    try:
        child = pexpect.spawn(command, logfile=None)
    except:
        return ExecRes(out=f'Failed to start new process: {command}: {sys.exc_info()}', ret=1)

    # child.interact()
    child.wait()
    output: str = child.read().decode("utf-8").rstrip()
    if echo_output:
        print(f'{output}')
    child.close()
    return ExecRes(out=output, ret=child.exitstatus)


shell_program_positive_cache: t.Set[str] = set()
def shell_program_exists(program: str) -> bool:
    if program in shell_program_positive_cache:
        return True

    # Output of "command -v uname" is totally useless even in DEBUG, so, echo_output=False
    result: bool = exec(False, f'bash -c "command -v {program}"', echo_output=False).is_ok()
    if result:
        shell_program_positive_cache.add(program)
    return result

class TestShellCommandExists(ut.TestCase):
    def test_existing_command_exist(self):
        self.assertTrue(shell_program_exists('uname'))

    def test_nonexisting_command_does_not_exist(self):
        self.assertFalse(shell_program_exists('unameqwer1324'))


@dc.dataclass
class ProgPack:
    program: str = ""
    package: str = ""

    def exec(self, dry_run: bool, command: str, root_is_required: bool = False) -> ExecRes:
        def install_if_program_does_not_exist(dry_run: bool, pp: ProgPack) -> None:
            if shell_program_exists(pp.program):
                return
            logger.warning(f'Program: {pp.program} does not exist => installing it via package: {pp.package}')
            res: ExecRes = exec(dry_run=dry_run, command=f'apt install -y {pp.package}', root_is_required=True)
            if res.is_err():
                logger.critical(f"Program: {pp.program} does not exist, and we failed to install it via package: "
                                f"{pp.package}: {res}")
            if not shell_program_exists(pp.program) and not dry_run:
                logger.critical(f"Program: {pp.program} still does not exist even after installing {pp.package}")

        install_if_program_does_not_exist(dry_run=dry_run, pp=self)
        return exec(dry_run=dry_run, command=command, root_is_required=root_is_required)


def install_if_file_does_not_exist(dry_run: bool, file: pl.Path, package: str) -> None:
    if file.exists():
        return
    logger.info(f'File: {file} does not exist => installing it via package: {package}')
    res: ExecRes = exec(dry_run=dry_run, command=f'apt install -y {package}')
    if res.is_err():
        logger.critical(f"File: {file} does not exist, and we failed to install it via package: "
                        f"{package}: {res}")
    if not file.exists() and not dry_run:
        logger.critical(f"File: {file} still does not exist even after installing {package}")













# ==============================================================================================================
# ==============================================================================================================
# SSL.
# The classes below work only with one given key/certificate - they do not know about DB/KEK/...

class SslEngine(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def sign(self, file: pl.Path, out: pl.Path):
        pass
    @abc.abstractmethod
    def verify(self, file: pl.Path):
        pass

    @staticmethod
    def key_path(dir: pl.Path, component: str) -> pl.Path:
        return dir / f'{component}.key' # Private key. Ex: .../PK.key
    @staticmethod
    def crt_path(dir: pl.Path, component: str) -> pl.Path:
        return dir / f'{component}.crt' # PEM-encoded certificate (public key + metainfo). Ex: .../PK.crt
    @staticmethod
    def cer_path(dir: pl.Path, component: str) -> pl.Path:
        return dir / f'{component}.cer' # DER-encoded certificate (public key + metainfo). Ex: .../PK.crt
    @staticmethod
    def esl_path(dir: pl.Path, component: str) -> pl.Path:
        return dir / f'{component}.esl' # EFI Sig List. Ex: .../PK.esl
    @staticmethod
    def auth_path(dir: pl.Path, component: str) -> pl.Path:
        return dir / f'{component}.auth' # signed ESL file. Ex: .../PK.auth



# SSL Engine implementation based that knows about key info on filesystem
class FsSsl(SslEngine):
    def __init__(self, dry_run: bool, path_to_basename: str) -> None:
        self.dry_run = dry_run
        self.basename = path_to_basename

    def sign(self, file: pl.Path, out: pl.Path):
        # sbsign --key dsk1.key --cert dsk1.crt shimx64.efi
        key_path: pl.Path = pl.Path(f'{self.basename}.key').expanduser().resolve()
        crt_path: pl.Path = pl.Path(f'{self.basename}.crt').expanduser().resolve()
        cmd: str = f'sbsign --key {key_path} --cert {crt_path} --output {out} {file}'
        res: ExecRes = ProgPack('sbsign', 'sbsigntool').exec(self.dry_run, cmd)
        if res.is_err():
            logger.critical(f'Failed to sign {file} with {key_path} and {crt_path} and/or save it to {out}: {res}')

    def verify(self, file: pl.Path):
        crt_path: pl.Path = pl.Path(f'{self.basename}.crt').expanduser().resolve()
        cmd: str = f'sbverify --cert {crt_path} {file}'
        res: ExecRes = ProgPack('sbverify', 'sbsigntool').exec(self.dry_run, cmd)
        if res.is_err():
            logger.critical(f'Failed to verify signed file: {file} with cert {crt_path}: {res}')


NFC_READER_HINT: str = ''

# SSL Engine implementation that can use Yubikey
class YubikeySsl(SslEngine):
    def __init__(self, dry_run: bool, work_dir: pl.Path, key_name: str, slot: str, pkcs11_obj: str, password: str) -> None:
        self.dry_run = dry_run
        self.password = password
        # self.work_dir = work_dir
        # self.slot = slot
        self.pkcs11_obj = pkcs11_obj
        work_dir = work_dir / ".SSL"
        work_dir.mkdir(parents=True, exist_ok=True)
        self.crt_path: pl.Path = SslEngine.crt_path(work_dir, key_name)
        YubikeySsl.extract_certificate(dry_run=self.dry_run, slot_id=slot, dst=self.crt_path)

    @staticmethod
    def extract_certificate(dry_run: bool, slot_id: str, dst: pl.Path) -> str:
        # yubico-piv-tool -a read-certificate -s 9c -o db_from_yu.crt -K PEM
        command: str = f'yubico-piv-tool {NFC_READER_HINT} -a read-certificate --slot {slot_id} -o {dst} -K PEM'
        res: ExecRes = ProgPack('yubico-piv-tool', 'yubico-piv-tool').exec(dry_run, command)
        if res.is_err():
            logger.critical(f'Failed read certificate from Yubikey, from slot {slot_id} and/or save it to {dst}: {res}')
        return command


    def sign(self, file: pl.Path, out: pl.Path):
        # sbsign --engine pkcs11 --key 'pkcs11:manufacturer=piv_II;id=%02' --cert PK.crt --output bzImage.signed.efi shimx64.efi

        # Without the package, sbsign with engine pkcs11 complains:
        # DSO support routines:dlfcn_load:could not load the shared
        # library:../crypto/dso/dso_dlfcn.c:118:filename(/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so):
        # /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so: cannot open shared object file: No such file or directory
        install_if_file_does_not_exist(dry_run=self.dry_run,
                                       file=pl.Path("/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so"),
                                       package="libengine-pkcs11-openssl")

        cmd: str = f"sbsign --engine pkcs11 --key '{self.pkcs11_obj}' --cert {self.crt_path} --output {out} {file}"
        logger.debug(f'{"NOT " if self.dry_run else ""}executing: {cmd}')
        if self.dry_run:
            return

        # Curses try #2: https://stackoverflow.com/questions/24946988/using-python-subprocess-call-to-launch-an-ncurses-process
        child = pexpect.spawn(cmd)
        child.expect('Enter engine key pass phrase:')
        child.sendline(self.password)
        child.expect('Enter PKCS#11 key PIN for .* key:')
        child.sendline(self.password)
        child.wait()
        child.close()
        if child.exitstatus != 0:
            logger.critical(f"Failed to sign {file} with {self.crt_path} and/or save result in {out}")

    def verify(self, file: pl.Path):
        FsSsl(self.dry_run, str(self.crt_path.with_suffix(""))).verify(file)


# ==============================================================================================================
# UEFI Keys and certificates

class UefiVars(Enum):
    PK = 1 # PK component name
    KEK = 2 # KEK component name
    db = 3 # db component name
    dbx = 4 # dbx component name

class UefiEngine(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def enroll_certs_to_uefi(self) -> None:
        pass
    @abc.abstractmethod
    def sign(self, file: pl.Path, out: pl.Path) -> None:
        pass
    @abc.abstractmethod
    def verify(self, file: pl.Path) -> str:
        pass
    @abc.abstractmethod
    def __str__(self) -> str:
        pass


# Responsible for operations with UEFI with key info on FileSystem
class FsUefi(UefiEngine):
    def __init__(self, dry_run: bool, keys_dir: pl.Path, var: UefiVars) -> None:
        self.dry_run = dry_run
        self.keys_dir = keys_dir
        self.var = var

    @staticmethod
    def enroll_certs_to_uefi_from_dir(dry_run: bool, dir: pl.Path) -> None:
        print(f'Not implemented yet.')
        print(f'You will need to do it manually:')
        print(f'  - Copy *.cer files from {dir} to a FAT-formatted flash drive, _or_ /boot/efi directory')
        print(f'  - Reboot and enter UEFI setup => SecureBoot settings')
        print(f'  - In the settings, remove all existing keys (PK, KEK, db)')
        print(f'  - Enroll your own (db.cer, KEK.cer, PK.cer)')
        # def enroll_esl(dry_run: bool, dir: pl.Path, esl_var: UefiVars) -> None:
        #     esl: pl.Path = SslEngine.esl_path(dir, esl_var.name)
        #     res: ExecRes = ProgPack('efi-updatevar', 'efitools').exec(dry_run,
        #                                                               f'efi-updatevar -e -f {esl} {esl_var.name}')
        #     if res.is_err():
        #         logger.critical(f'Failed to enroll: {esl}: {res}')
        #     logger.info(f'Successfully enrolled {esl_var.name}: {esl}')
        #
        # # Install keys into EFI (PK last as it will enable Custom Mode locking out further unsigned changes):
        # enroll_esl(dry_run, dir, esl_var=UefiVars.db) # sudo efi-updatevar -e -f sec_out/db.esl db
        # enroll_esl(dry_run, dir, esl_var=UefiVars.KEK) # sudo efi-updatevar -e -f sec_out/KEK.esl KEK
        # enroll_esl(dry_run, dir, esl_var=UefiVars.PK) # sudo efi-updatevar -f sec_out/PK.auth PK
        # # sudo efi-updatevar -e -c sec_out/db.crt db
        # # sudo efi-updatevar -e -c sec_out/KEK.crt KEK
        # # sudo efi-updatevar -e -c sec_out/PK.crt PK
        # # sudo efi-updatevar -f sec_out/PK.auth PK
        # # sudo efi-updatevar -e -f sec_out/PK.auth PK
        #
        # # The EFI variables may be immutable (i-flag in lsattr output) in recent kernels (e.g. 4.5.4).
        # # Use chattr -i to make them mutable again if you can’t update the variables with the commands above:
        # # chattr -i /sys/firmware/efi/efivars/{PK,KEK,db,dbx}-*

    def enroll_certs_to_uefi(self) -> None:
        self.enroll_certs_to_uefi_from_dir(self.dry_run, self.keys_dir)

    def sign(self, file: pl.Path, out: pl.Path) -> None:
        FsSsl(dry_run=self.dry_run, path_to_basename=str(self.keys_dir / self.var.name)).sign(file, out)

    def verify(self, file: pl.Path) -> str:
        FsSsl(dry_run=self.dry_run, path_to_basename=str(self.keys_dir / self.var.name)).verify(file)
        return f'"pesign -S -i {file}" and/or ' \
               f'"sbverify --cert {(self.keys_dir / (self.var.name + ".crt")).resolve()} {file}"'

    def __str__(self) -> str:
        return f'FsUefi({self.keys_dir / self.var.name})'

    @staticmethod
    def generate_keys(dry_run: bool, keys_dir: pl.Path, id: str) -> None:
        def id_for(name: str, id: str) -> str: # "PK of Asdf" or "Custom PK"
            return f'{name} of {id}' if id else f'Custom {name}'

        def generate(dry_run: bool, output_dir: pl.Path, id: str, var: UefiVars):
            # openssl req –new -x509 –newkey rsa:2048 –subj "/CN=Custom PK/" –keyout PK.key   –out PK.crt   –days 3650 –nodes –sha256
            # openssl x509 -outform der -in PK.crt   -out PK.cer
            # cert-to-efi-sig-list -g (uuidgen) sec_out/PK.crt sec_out/PK.esl
            key_out: pl.Path = SslEngine.key_path(output_dir, var.name)
            crt_out: pl.Path = SslEngine.crt_path(output_dir, var.name)
            cer_out: pl.Path = SslEngine.cer_path(output_dir, var.name)
            esl_out: pl.Path = SslEngine.esl_path(output_dir, var.name)
            gen_res: ExecRes = ProgPack('openssl', 'openssl').exec(dry_run,
                                                                   f'openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 '
                                                                   f'-subj "/CN={id_for(var.name, id)}/" -keyout {key_out} -out {crt_out}')
            if gen_res.is_ok():
                logger.info(f'Generated private key in {key_out}, cert in {crt_out}. You might want to check that '
                            f'everything is fine: "openssl x509 -inform pem -in {crt_out} -text"')
            else:
                logger.critical(f'Failed to generate {var.name} and/or save it to {key_out} and {crt_out}: {gen_res}')

            cer_res: ExecRes = ProgPack('openssl', 'openssl').exec(dry_run,
                                                                   f'openssl x509 -outform der -in {crt_out} -out {cer_out}')
            if cer_res.is_ok():
                logger.info(f'Converted PEM-encoded .crt to DER-encoded .cer at: {cer_out}')
            else:
                logger.critical(f'Failed to convert PEM-encoded .crt to DER-encoded .cer and/or save it to {cer_out}: {cer_res}')

            # esl_res: ExecRes = ProgPack('cert-to-efi-sig-list', 'efitools').exec(dry_run,
            #                                                                      f'bash -c "cert-to-efi-sig-list -g $(uuidgen) {cer_out} {esl_out}"')
            # if esl_res.is_ok():
            #     logger.info(f'Converted cer {cer_out} to esl: {esl_out}')
            # else:
            #     logger.critical(f'Failed to convert cer {cer_out} to esl and/or save it to {esl_out}: {esl_res}')

        # def sign_esl(dry_run: bool, output_dir: pl.Path, var_to_sign: UefiVars, with_var: UefiVars) -> None:
        #     with_key: pl.Path = SslEngine.key_path(output_dir, with_var.name)
        #     with_crt: pl.Path = SslEngine.crt_path(output_dir, with_var.name)
        #     esl_to_sign: pl.Path = SslEngine.esl_path(output_dir, var_to_sign.name)
        #     auth_out: pl.Path = SslEngine.auth_path(output_dir, var_to_sign.name)
        #     res: ExecRes = ProgPack('sign-efi-sig-list', 'efitools').exec(dry_run,
        #                  f'sign-efi-sig-list -k {with_key} -c {with_crt} {var_to_sign.name} {esl_to_sign} {auth_out}')
        #     if res.is_err():
        #         logger.critical(f'Failed to sign esl: {esl_to_sign} with {with_var.name} '
        #                         f'and/or save it to {auth_out}: {res}')
        #     logger.info(f'Signed esl: {esl_to_sign} with {with_var.name}: {auth_out}')


        keys_dir.mkdir(parents=True, exist_ok=True)

        generate(dry_run=dry_run, output_dir=keys_dir, id=id, var=UefiVars.PK)
        generate(dry_run=dry_run, output_dir=keys_dir, id=id, var=UefiVars.KEK)
        generate(dry_run=dry_run, output_dir=keys_dir, id=id, var=UefiVars.db)

        # Some tools require the use of signed ESL files - AUTH files - even when Secure Boot is not enforcing or
        # does not have a PK loaded. Only AUTH files can be used to carry out updates to Secure Boot's value stores
        # while Secure Boot is enforcing checks. So, let's generate AUTH files, in case they are needed.
        # sign_esl(dry_run=dry_run, output_dir=keys_dir, var_to_sign=UefiVars.PK, with_var=UefiVars.PK)
        # sign_esl(dry_run=dry_run, output_dir=keys_dir, var_to_sign=UefiVars.KEK, with_var=UefiVars.PK)
        # sign_esl(dry_run=dry_run, output_dir=keys_dir, var_to_sign=UefiVars.db, with_var=UefiVars.KEK)

# Responsible for operations with UEFI with key info on Yubikey
class YubikeyUefi(UefiEngine):
    def __init__(self, dry_run: bool, work_dir: pl.Path, var: UefiVars, password: str) -> None:
        self.dry_run = dry_run
        self.work_dir = work_dir
        self.var = var
        self.password = password
        self.ssl = None

    def enroll_certs_to_uefi(self) -> None:
        def extract(dry_run: bool, var: UefiVars, work_dir: pl.Path):
            YubikeySsl.extract_certificate(dry_run=dry_run,
                                           slot_id=YubikeyUefi.slot_for(var),
                                           dst=SslEngine.crt_path(work_dir, var.name))

        with tempf.TemporaryDirectory(prefix="secboot_certs_for_uefi_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            extract(self.dry_run, UefiVars.PK, work_dir)
            extract(self.dry_run, UefiVars.KEK, work_dir)
            extract(self.dry_run, UefiVars.db, work_dir)
            FsUefi.enroll_certs_to_uefi_from_dir(dry_run=self.dry_run, dir=work_dir)
            input('\nPress any key to exit...')


    def _slot(self):
        return YubikeyUefi.slot_for(self.var)
    def _pkcs11(self):
        return YubikeyUefi.pkcs11_obj_for(self.var)
    def _ssl(self):
        if self.ssl:
            return self.ssl
        self.ssl = YubikeySsl(dry_run=self.dry_run,
                              work_dir=self.work_dir,
                              key_name=self.var.name,
                              slot=self._slot(),
                              pkcs11_obj=self._pkcs11(),
                              password=self.password)
        return self.ssl

    def sign(self, file: pl.Path, out: pl.Path) -> None:
        self._ssl().sign(file, out)

    def verify(self, file: pl.Path) -> str:
        self._ssl().verify(file)
        extract_command: str = YubikeySsl.extract_certificate(dry_run=True,
                                                              slot_id=self._slot(),
                                                              dst=pl.Path(f'{self.var.name}.crt'))
        return f'"pesign -S -i {file}" and/or "sbverify --cert {self.var.name}.crt {file}", ' \
               f'where "{self.var.name}.crt" is extracted from Yubikey with: "{extract_command}"'

    def __str__(self) -> str:
        return f'YubikeyUefi({self.var.name} in slot: {self._slot()}, {self._pkcs11()})'

    @staticmethod
    def enroll_to_yubikey(dry_run: bool, dir: pl.Path) -> None:
        logger.warning(f'You might want to setup your Yubikey: '
                       f'(1) Set PIN: "yubico-piv-tool {NFC_READER_HINT} --action change-pin -P 123456", '
                       f'(2) Set PUK: "yubico-piv-tool {NFC_READER_HINT} --action change-puk -P 12345678", '
                       f'(3) Enable PIV over NFC: "ykman config nfc -f -e PIV". '
                       f'Other action see here: https://developers.yubico.com/yubico-piv-tool/Actions/')

        def enable_retired_slots(dry_run: bool) -> None:
            # http://cedric.dufour.name/blah/IT/YubiKeyHowto.html
            # escaped_nfc_reader_hint = NFC_READER_HINT.replace('"', '\\"')
            res: ExecRes = ProgPack('yubico-piv-tool', 'yubico-piv-tool').exec(dry_run,
               f'bash -c "echo -n C10114C20100FE00 | yubico-piv-tool {NFC_READER_HINT} -a write-object --id 0x5FC10C -i -"')
            if res.is_err():
                logger.critical(f'Failed to enable retired slots: {res}')
            logger.info(f'Retired slots enabled')

        def enroll(dry_run: bool, dir: pl.Path, var: UefiVars) -> None:
            # yubico-piv-tool --action import-key         --slot 82 --input PK.key --key-format PEM
            # yubico-piv-tool --action import-certificate --slot 82 --input PK.crt --key-format PEM

            slot: str = YubikeyUefi.slot_for(var)
            key_in: pl.Path = SslEngine.key_path(dir, var.name)
            crt_in: pl.Path = SslEngine.crt_path(dir, var.name)
            ikcmd: str = f'yubico-piv-tool {NFC_READER_HINT} -a import-key --slot {slot} --input {key_in} --key-format PEM'
            key_res: ExecRes = ProgPack('yubico-piv-tool', 'yubico-piv-tool').exec(dry_run, ikcmd)
            if key_res.is_err():
                logger.critical(f'Failed to add key: {key_in} in slot: {slot}')
            logger.info(f'Added key: {key_in} in slot: {slot}')

            iccmd: str = f'yubico-piv-tool {NFC_READER_HINT} -a import-certificate --slot {slot} --input {crt_in} --key-format PEM'
            crt_res: ExecRes = ProgPack('yubico-piv-tool', 'yubico-piv-tool').exec(dry_run, iccmd)
            if crt_res.is_err():
                logger.critical(f'Failed to add certificate: {crt_in} in slot: {slot}')
            logger.info(f'Added certificate: {crt_in} in slot: {slot}')

        enable_retired_slots(dry_run)
        enroll(dry_run, dir, UefiVars.PK)
        enroll(dry_run, dir, UefiVars.KEK)
        enroll(dry_run, dir, UefiVars.db)


    @staticmethod
    def slot_for(var: UefiVars) -> str:
        return YubikeyUefi._YUBIKEY_SLOT_MAPPING[var][0]
    @staticmethod
    def pkcs11_obj_for(var: UefiVars) -> str:
        return YubikeyUefi._YUBIKEY_SLOT_MAPPING[var][1]

    # Slot 9c: Digital Signature <-> KEK
    # This certificate and its associated private key is used for digital signatures for the purpose of document
    # signing, or signing files and executables.
    # Slot 9d: Key Management <-> DB
    # This certificate and its associated private key is used for encryption for the purpose of confidentiality.
    # This slot is used for things like encrypting e-mails or files.
    # Other slots naming and mapping: https://developers.yubico.com/yubico-piv-tool/YKCS11/Functions_and_values.html
    # Slot 82: Private key for Retired Key 1 <-> PK
    # You can find "id=%05" via:
    # apt install gnutls-bin ykcs11
    # p11tool --provider /usr/lib/x86_64-linux-gnu/libykcs11.so --list-privkeys --login
    _YUBIKEY_SLOT_MAPPING: t.Dict[UefiVars, t.Tuple[str, str]] = {
        UefiVars.PK: ("82", "pkcs11:manufacturer=piv_II;id=%05"), # Retired Key 1
        UefiVars.KEK: ("9d", "pkcs11:manufacturer=piv_II;id=%03"), # Key Management
        UefiVars.db: ("9c", "pkcs11:manufacturer=piv_II;id=%02"), # Digital Signature
    }


BACKUP_CERTS_FROM_UEFI_CMD_LINE_OPT: str = "ot/backup-certs-from-uefi"
def backup_certs_from_uefi(dry_run: bool, output_dir: pl.Path) -> None:
    # efi-readvar -v PK -o PK.old.esl
    def save(dry_run: bool, output_dir: pl.Path, var_name: str, file_name: str):
        out = str(output_dir / file_name)
        res: ExecRes = ProgPack('efi-readvar', 'efitools').exec(dry_run, f'efi-readvar -v {var_name} -o {out}')
        if res.is_ok():
            logger.info(f'Saved {var_name} to {out}. You might want to extract der certificates from it with: '
                        f'"sig-list-to-certs {out} {var_name}" and inspect it further with '
                        f'"openssl x509 -inform der -in {var_name}-<n>.der -text"')
        else:
            logger.critical(f'Failed to save {var_name} to {out}: {res}')

    output_dir.mkdir(parents=True, exist_ok=True)
    save(dry_run, output_dir, UefiVars.PK.name, f'{UefiVars.PK.name}.old.esl')
    save(dry_run, output_dir, UefiVars.KEK.name, f'{UefiVars.KEK.name}.old.esl')
    save(dry_run, output_dir, UefiVars.db.name, f'{UefiVars.db.name}.old.esl')
    save(dry_run, output_dir, UefiVars.dbx.name, f'{UefiVars.dbx.name}.old.esl')


def remove_all_ssl_signatures_inplace(dry_run: bool, filepath: pl.Path) -> None:
    def get_number_of_signatures(dry_run: bool, filepath: pl.Path) -> int:
        res: ExecRes = ProgPack('pesign', 'pesign').exec(dry_run, f'pesign -S -i {filepath}')
        if res.is_err():
            logger.critical(f'Failed to get signatures from {filepath}: {res}')

        # Example of output:
        # ---------------------------------------------
        # certificate address is 0x7f591bf17f80
        # Content was not encrypted.
        # Content is detached; signature cannot be verified.
        # The signer's common name is Canonical Ltd. Secure Boot Signing (2017)
        # ...
        # ---------------------------------------------
        # certificate address is 0x7f591bf18700
        # Content was not encrypted.
        # Content is detached; signature cannot be verified.
        # The signer's common name is Microsoft Windows UEFI Driver Publisher
        # ...
        # ---------------------------------------------

        # Or
        # No signatures found.

        if dry_run:
            return 2
        count: int = res.out.count("---------------------------------------------")
        return 0 if count == 0 else count - 1

    def remove_one_signature(dry_run: bool, inp: pl.Path, out: pl.Path) -> None:
        # pesign --signature-number 0 -r -i shimx64.efi -o shimx64.efi
        res: ExecRes = ProgPack('pesign', 'pesign').exec(dry_run,
                                                         f'pesign --signature-number 0 --remove-signature -i {inp} -o {out}')
        if res.is_ok():
            logger.debug(f'Removed existing signature from {inp}, and wrote result in {out}')
        else:
            logger.critical(f'Failed to remove existing signature from {inp} and/or save result in {out}: {res}')


    number_of_signatures: int = get_number_of_signatures(dry_run=dry_run, filepath=filepath)
    logger.debug(f'{number_of_signatures} signatures found in {filepath}. '
                 f'{"Removing them..." if number_of_signatures else "Nothing to remove."}')
    if number_of_signatures == 0:
        return

    tmp_filepath: pl.Path = filepath.with_suffix(f'{filepath.suffix}.tmp')
    for i in range(0, number_of_signatures):
        safe_move(dry_run=dry_run, src=filepath, dst=tmp_filepath)
        remove_one_signature(dry_run=dry_run, inp=tmp_filepath, out=filepath)
    safe_rm(dry_run=dry_run, path=tmp_filepath)



GENERATE_UEFI_KEYS_CMD_LINE_OPT: str = "ot/generate-uefi-keys"

ENROLL_SSL_TO_YUBIKEY_CMD_LINE_OPT: str = "ot/enroll-ssl-to-yubikey"

ENROLL_SSL_TO_UEFI_CMD_LINE_OPT: str = "ot/enroll-certs-to-uefi"

RE_SIGN_EFI_FILE_CMD_LINE_OPT: str = "re-sign-efi-file"

def re_sign_efi_file(dry_run: bool,
                     file_to_sign: pl.Path,
                     signed_file_path: pl.Path,
                     uefi: UefiEngine,
                     do_log: bool = True):
    remove_all_ssl_signatures_inplace(dry_run=dry_run, filepath=file_to_sign)
    uefi.sign(file_to_sign, signed_file_path)
    verify_desc = uefi.verify(signed_file_path)
    if do_log:
        logger.info(f'(Re-)signed and verified {signed_file_path} with {uefi}. '
                    f'You can verify it yourself with {verify_desc}')


















# ==============================================================================================================
# ==============================================================================================================
# GPG

def write_gpg_conf(dry_run: bool, gpg_home: pl.Path) -> None:
    # wget -O $GNUPGHOME/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf
    GPG_CONFIG: str = """
# https://github.com/drduh/config/blob/master/gpg.conf
# https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
# https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html
# Use AES256, 192, or 128 as cipher
personal-cipher-preferences AES256 AES192 AES
# Use SHA512, 384, or 256 as digest
personal-digest-preferences SHA512 SHA384 SHA256
# Use ZLIB, BZIP2, ZIP, or no compression
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
# Default preferences for new keys
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
# SHA512 as digest to sign keys
cert-digest-algo SHA512
# SHA512 as digest for symmetric ops
s2k-digest-algo SHA512
# AES256 as cipher for symmetric ops
s2k-cipher-algo AES256
# UTF-8 support for compatibility
charset utf-8
# Show Unix timestamps
fixed-list-mode
# No comments in signature
no-comments
# No version in output
no-emit-version
# Disable banner
no-greeting
# Long hexidecimal key format
keyid-format 0xlong
# Display UID validity
list-options show-uid-validity
verify-options show-uid-validity
# Display all keys and their fingerprints
with-fingerprint
# Display key origins and updates
#with-key-origin
# Cross-certify subkeys are present and valid
require-cross-certification
# Disable caching of passphrase for symmetrical ops
no-symkey-cache
# Enable smartcard
use-agent
# Disable recipient key ID in messages
throw-keyids
# Keyserver URL
#keyserver hkps://keys.openpgp.org
#keyserver hkps://keyserver.ubuntu.com:443
#keyserver hkps://hkps.pool.sks-keyservers.net
#keyserver hkps://pgp.ocf.berkeley.edu
# Proxy to use for keyservers
#keyserver-options http-proxy=http://127.0.0.1:8118
#keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050
# Verbose output
#verbose
# Show expired subkeys
#list-options show-unusable-subkeys
"""

    if dry_run:
        return

    with open(gpg_home / "gpg.conf", "w") as gpg_conf:
        gpg_conf.write(GPG_CONFIG)



@dc.dataclass
class FileAndSig:
    file: pl.Path
    sig: pl.Path
    def default_sig(self) -> pl.Path:
        return self.file.with_suffix(self.file.suffix + ".sig")
    def __init__(self, f: pl.Path, s: t.Union[pl.Path, None] = None) -> None:
        self.file = f
        self.sig = self.default_sig() if s is None else s
    def __repr__(self):
        return f'FileWithGpgSig({self.file}, {self.sig})'


class Gpg:
    def __init__(self, dry_run: bool, GNUPGHOME: pl.Path, key_id: str, password: t.Union[None, str]):
        self.dry_run = dry_run
        self.GNUPGHOME = GNUPGHOME
        self.key_id = key_id
        self.password = password

    def sign_detached(self, file_and_sig: FileAndSig) -> None:
        # gpg --default-key $KEYID --detach-sign sec_out/shimx64.efi
        if self.password is None:
            cmd: str = f'gpg --yes --default-key {self.key_id} --detach-sign {file_and_sig.file}'
        else:
            cmd: str = f'gpg --passphrase "{self.password}" --pinentry-mode loopback --batch ' \
                       f'--yes --default-key {self.key_id} --detach-sign {file_and_sig.file}'

        res: ExecRes = self.exec_in_home(cmd)
        if res.is_err():
            logger.critical(f"Failed to sign {file_and_sig.file}")
        safe_move(self.dry_run, file_and_sig.default_sig(), file_and_sig.sig)

    def verify(self, file_and_sig: FileAndSig) -> str:
        # gpg --verify sec_out/shimx64.efi.sig sec_out/shimx64.efi
        # gpg: Signature made Mon 19 Apr 2021 17:56:17 BST
        # gpg:                using RSA key FCC...
        # gpg: Good signature from "..." [unknown]
        res: ExecRes = self.exec_in_home(f'gpg --verify {file_and_sig.sig} {file_and_sig.file}')
        if res.is_err():
            logger.critical(f"Failed to verify {file_and_sig.file} against signature: {file_and_sig.sig}: {res}")
        return f'"gpg --verify {file_and_sig.sig} {file_and_sig.file}"'

    def export_pub_key(self, work_dir: pl.Path) -> pl.Path:
        # gpg --export $GPG_KEY > gpg.key
        result: pl.Path = work_dir / 'gpg_pub.key'
        res: ExecRes = self.exec_in_home(f'bash -c "gpg --export {self.key_id} > {result}"')
        if res.is_err():
            logger.critical(f"Failed to export public key of {self.key_id}: {res}")
        return result

    def exec_in_home(self, cmd: str) -> ExecRes:
        return Gpg.exec_in(dry_run=self.dry_run, in_dir=self.GNUPGHOME, cmd=cmd)
    @staticmethod
    def exec_in(dry_run: bool, in_dir: pl.Path, cmd: str) -> ExecRes:
        os.environ["GNUPGHOME"] = str(in_dir)
        res: ExecRes = ProgPack('gpg', 'gpg').exec(dry_run, cmd)
        del os.environ["GNUPGHOME"]
        return res

    def __str__(self) -> str:
        return f'Gpg({self.GNUPGHOME}, key_id: {self.key_id})'

    @staticmethod
    def get_last_added_primary_key_fingerprint(dry_run: bool, gpg_home: pl.Path) -> str:
        # gpg --list-keys --with-fingerprint --with-colons | tac | grep "^fpr:" | head -n 1 | cut -d : -f 10
        res: ExecRes = Gpg.exec_in(dry_run, gpg_home,
                                   f'bash -c "gpg --list-keys --with-fingerprint --with-colons 2>/dev/null | '
                                   f'tac | grep \"^fpr:\" | head -n 1 | cut -d : -f 10"')
        if res.is_err():
            logger.critical(f'Failed to get fingerpriint of primary key: {res}')
        return res.out

    @staticmethod
    def generate_keys(dry_run: bool, gpg_home: pl.Path, id: str, passphrase: str) -> None:
        # https://serverfault.com/a/962553/304045
        # https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html
        # gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "Generate BatchKey" rsa4096 cert never
        # gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key 54203CB155CD20D034994814F17CED43965D5D69 rsa4096 sign never
        # gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key 54203CB155CD20D034994814F17CED43965D5D69 rsa4096 encrypt never
        # gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key 54203CB155CD20D034994814F17CED43965D5D69 rsa4096 auth never

        if not dry_run:
            gpg_home.mkdir(parents=True, exist_ok=True)
        if not (gpg_home / "gpg.conf").exists():
            write_gpg_conf(dry_run, gpg_home)

        primary_res: ExecRes = Gpg.exec_in(dry_run, gpg_home,
                                           f'gpg --batch --pinentry-mode loopback --passphrase "{passphrase}" '
                                           f'--quick-generate-key "{id}" rsa4096 cert never')
        if primary_res.is_err():
            logger.critical(f'Failed to generate primary key: {primary_res}')
        key_id: str = Gpg.get_last_added_primary_key_fingerprint(dry_run, gpg_home)

        logger.info(f'Generated primary rsa4096 cert key with keyid: {key_id}')

        def add_sub_key(dry_run: bool, keys_dir: pl.Path, key_id: str, passphrase: str, usage: str) -> None:
            res: ExecRes = Gpg.exec_in(dry_run, keys_dir,
                                       f'gpg --batch --pinentry-mode loopback --passphrase "{passphrase}" '
                                       f'--quick-add-key {key_id} rsa4096 {usage} never')
            if res.is_err():
                logger.critical(f'Failed to add {usage} key to {key_id}: {res}')
            logger.info(f'Generated sub-key: rsa4096 {usage}')

        add_sub_key(dry_run, gpg_home, key_id, passphrase, "sign")
        add_sub_key(dry_run, gpg_home, key_id, passphrase, "encrypt")
        add_sub_key(dry_run, gpg_home, key_id, passphrase, "auth")

        print(f"""
Done

- What have been done:
More info is here: https://github.com/drduh/YubiKey-Guide


- Next steps:
  * Set GPG Home env var:
    (fish) set -x GNUPGHOME {gpg_home}
    (bash) export GNUPGHOME={gpg_home}

  * Save (and upload to a keyserver) GPG public key:
    gpg --armor --export {key_id} | sudo tee /mnt/home/.../gpg-{key_id}.asc

  * Save revocation certificate:
    sudo cp {gpg_home}/openpgp-revocs.d/{key_id}.rev /mnt/home/.../

  * Move keys to Yubikey:
    0. Read this item only if you are going to move same keys to multiple Yubikeys.
       Moving keys is a destructive process (you will NOT have private keys locally after you moved them to a Yubikey).
       So, you have to backup {gpg_home} in order to be able to restore it later, and move same keys again to a different Yubikey.
       Also, gpg remembers IDs of Yubikeys, if you want to use a new Yubikey (with same key), ask gpg to re-record id of the new Yubikey:
       gpg-connect-agent "scd serialno" "learn --force" /bye
    1. Install packages:
       sudo apt update && sudo apt install cryptsetup opensc scdaemon pcscd yubikey-luks yubikey-manager yubikey-personalization yubikey-personalization-gui libpam-yubico libpam-u2f
    2. Setup card:
       gpg --card-edit
          * admin
          * kdf-setup
          * passwd (Default PIN: 123456, new PIN must be >=6 characters. Default Admin PIN: 12345678, new Admin PIN must be >=8 characters.)
             * change PUK
             * change PIN
          * name
          * login
          * list
          * quit
       If you need to reset GPG at Yubikey (https://developers.yubico.com/ykneo-openpgp/ResetApplet.html):
          * pkill -9 -f "(gpg-agent|gpg-connect-agent)"
          * gpg-connect-agent --hex "scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40" /bye # 4 times
          * gpg-connect-agent --hex "scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40" /bye # 4 times
          * gpg-connect-agent --hex "scd apdu 00 e6 00 00" /bye
          * gpg-connect-agent --hex "scd apdu 00 44 00 00" /bye
          * pkill -9 -f "(gpg-agent|gpg-connect-agent)"
          * Remove and re-insert the Yubikey.
    3. Move the private keys to Yubikey:
       gpg --edit-key {key_id}
          key 1
          keytocard
          key 1
          key 2
          keytocard
          key 2
          key 3
          keytocard
          key 3
          save

  * Add public key to your default keyring:
    At another terminal (where you have NOT modified GNUPGHOME):
    gpg --import gpg-{key_id}.asc
    gpg --edit-key {key_id}
       * trust
         5
       * quit
""")



GENERATE_GPG_KEYS_CMD_LINE_OPT: str = "ot/generate-gpg-keys"

RE_SIGN_FILE_WITH_GPG_CMD_LINE_OPT: str = "re-sign-file-with-gpg"
def re_sign_file_with_gpg(dry_run: bool, file_and_sig: FileAndSig, gpg: Gpg, do_log: bool = True) -> str:
    gpg.sign_detached(file_and_sig)
    verify_cmd: str = gpg.verify(file_and_sig)
    if do_log:
        logger.info(f'Signed and verified {file_and_sig.file} with {gpg}. Signature: {file_and_sig.sig}. '
                    f'You can verify it yourself with {verify_cmd}')
    return verify_cmd





# The following 3 classes solve the following problem:
# When we use Yubikey for GPG operations, and immediately afterwards for PIV/SSL PIV/SSL *fails*.
# It *probably* happens because common resources (socket /run/pcscd/pcscd.comm?) is busy with
# gpg/gpg-agent, which prevents PIV/SSL from working properly.
#
# Solution to the problem is also mysterious - removing GPG home directory helps
# (obviously, only temporary Yubikey one that corresponds to Yubikey, not the permanent user's).
# That is why we need __enter__, __exit__, context manager.
# In the case of FsGpg they do nothing, in the case of YubikeyGpg they create and delete temporary GPG home
class WrappedGpg(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __str__(self) -> str:
        pass
    @abc.abstractmethod
    def __enter__(self) -> Gpg:
        pass
    @abc.abstractmethod
    def __exit__(self, exc_type, exc_value, tb) -> None:
        pass

# Knows about GPG on FS
class WrappedFsGpg(WrappedGpg):
    def __init__(self, dry_run: bool, password: t.Union[None, str], GNUPGHOME: pl.Path, key_id: str):
        self.dry_run = dry_run
        self.GNUPGHOME = GNUPGHOME
        self.key_id = key_id
        self.password = password
    def __str__(self) -> str:
        return f'WrappedFsGpg({self.GNUPGHOME}, KeyId: {self.key_id})'
    def __enter__(self) -> Gpg:
        return Gpg(self.dry_run, self.GNUPGHOME, self.key_id, password=self.password)
    def __exit__(self, exc_type, exc_value, tb) -> None:
        pass

# Knows about GPG on Yubikey
class WrappedYubikeyGpg(WrappedGpg):
    def __init__(self, dry_run: bool, password: t.Union[None, str], work_dir: pl.Path, pub_key: pl.Path):
        self.dry_run = dry_run
        self.work_dir = work_dir
        self.pub_key = pub_key
        self.password = password
        self.gpg = None

    def __str__(self) -> str:
        return f'WrappedYubikeyGpg({self.work_dir}, Key: {self.pub_key})'
    def __enter__(self) -> Gpg:
        # export GNUPGHOME=$(mktemp -d) # export GNUPGHOME=(mktemp -d)
        # KEYID=`gpg --import $HOME/pub_key.txt 2>&1 | grep -oP 'gpg: key \K(.*)(?=: public key )'
        # echo "trusted-key $KEYID" >> $GNUPGHOME/.gpg.conf
        # gpg --card-status
        GNUPGHOME: pl.Path = pl.Path() if self.dry_run else pl.Path(tempf.mkdtemp(prefix=".gnupg_", dir=self.work_dir))
        logger.debug(f'Initialising GPG in: {GNUPGHOME}')

        if not self.dry_run:
            write_gpg_conf(self.dry_run, GNUPGHOME)

        cmd: str = f'bash -c "gpg --import {self.pub_key} 2>&1 | grep -oP \'gpg: key \K(.*)(?=: public key )\''
        res: ExecRes = Gpg.exec_in(dry_run=self.dry_run, in_dir=GNUPGHOME, cmd=cmd)
        if res.is_err():
            logger.critical(f"Failed to import public GPG key from {self.pub_key} and obtain its id: {res}")
        key_id: str = res.out

        st_res: ExecRes = Gpg.exec_in(dry_run=self.dry_run, in_dir=GNUPGHOME, cmd=f'gpg --card-status')
        if st_res.is_err():
            logger.critical(f'Something is wrong with Yubikey/NFC, try to remove and insert it again and/or killing '
                            f'everything that can interfere with it: "sudo killall -r gpg scdaemon pcscd". {st_res}')

        self.gpg = Gpg(self.dry_run, GNUPGHOME, key_id, password=self.password)
        return self.gpg

    def __exit__(self, exc_type, exc_value, tb) -> None:
        safe_rm_dir(self.dry_run, self.gpg.GNUPGHOME)
        self.gpg = None




















# ==============================================================================================================
# ==============================================================================================================
# Common boot

def make_boot_backup(dry_run: bool, boot_dir: pl.Path, backups_dir: pl.Path) -> None:
    logger.info(f'Backing up {boot_dir}...')
    backup_dir: pl.Path = backups_dir / f'boot.bak.{time.time()}'
    if not dry_run:
        backup_dir.mkdir(parents=True)
    res: ExecRes = exec(dry_run, command=f"cp -r {boot_dir} {backup_dir}", echo_output=True, root_is_required=True)
    if res.is_err():
        logger.critical(f'Failed to backup boot: {res}')


@dc.dataclass
class KernelVersion:
    p1: int
    p2: int
    p3: int
    p4: int
    suffix: str
    def to_string(self, prefix: str = "") -> str:
        return f'{prefix}{self.p1}.{self.p2}.{self.p3}-{self.p4}-{self.suffix}'
    def __lt__(self, other):
        return (self.p1, self.p2, self.p3, self.p4) < (other.p1, other.p2, other.p3, other.p4)
    def __eq__(self, other):
        return (self.p1, self.p2, self.p3, self.p4) == (other.p1, other.p2, other.p3, other.p4)

    @staticmethod
    def regex(with_prefix: bool = True):
        if with_prefix:
            #                  vmlinuz-5.11.0-14-generic
            return re.compile(r'vmlinuz-(?P<g1>\d+).(?P<g2>\d+).(?P<g3>\d+)-(?P<g4>\d+)-(?P<g5>\w+$)')
        else:
            return re.compile(r'(?P<g1>\d+).(?P<g2>\d+).(?P<g3>\d+)-(?P<g4>\d+)-(?P<g5>\w+$)')

    @staticmethod
    def matches(basename: str, with_prefix: bool = True) -> bool:
        return bool(KernelVersion.regex(with_prefix).match(basename))

    @staticmethod
    def get_latest(dry_run: bool, n: int, boot_dir: pl.Path) -> t.List['KernelVersion']:
        res: t.List[KernelVersion] = []
        if dry_run:
            return [KernelVersion(1, 2, 3, 4, "generic")]
        for file_name in os.listdir(boot_dir):
            m = KernelVersion.regex().match(file_name)
            if not m:
                continue
            res.append(KernelVersion(int(m.group('g1')),
                                     int(m.group('g2')),
                                     int(m.group('g3')),
                                     int(m.group('g4')),
                                     m.group('g5')))
        res.sort(reverse=True)
        return res[:n]

class TestKernelVersion(ut.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
    def test_test(self):
        ok: t.List[str] = ["vmlinuz-1.2.3-4-generic"]
        not_ok: t.List[str] = [
            "vmlinuz-1.2.3-4-generic.bak"
        ]
        for o in ok:
            self.assertTrue(KernelVersion.matches(o))
        for no in not_ok:
            self.assertFalse(KernelVersion.matches(no))







# ==============================================================================================================
# ==============================================================================================================
# GRUB / GRUB Configs / Kernels / Initrds


# Docs:
# https://ruderich.org/simon/notes/secure-boot-with-grub-and-signed-linux-and-initrd
# https://fit-pc.com/wiki/index.php?title=Linux_Mint_19:_Secure_Boot

# Create GRUB trampoline config
#
# pbkdf2
# lsblk -f | grep -i efi | grep -E -o "[A-Z0-9]{4}-[A-Z0-9]{4}"
# export GPG_KEY=A4A24C5E8B528A2EB48DFB69A5FD402DA7D0343E
# gpg --yes --default-key "$GPG_KEY" --detach-sign "$TMP_GRUB_CFG"


# Create GRUB standalone image with the config
#
# MODULES="all_video archelp boot bufio configfile crypto echo efi_gop efi_uga ext2 extcmd  \
# fat font fshelp gcry_dsa gcry_rsa gcry_sha1 gcry_sha512 gettext gfxterm linux linuxefi ls \
# memdisk minicmd mmap mpi normal part_gpt part_msdos password_pbkdf2 pbkdf2 reboot relocator \
# search search_fs_file search_fs_uuid search_label sleep tar terminal verifiers video_fb"
#
# gpg --export $GPG_KEY > gpg.key
# grub-mkstandalone --directory /usr/lib/grub/x86_64-efi --format x86_64-efi --modules "$MODULES" --pubkey gpg.key
# --output grubx64.efi  boot/grub/grub.cfg=grub.init.cfg boot/grub/grub.cfg.sig=grub.init.cfg.sig


# Sign grubx64.efi with db => grubx64.efi.signed
# ...

# (Re-)Generate grub.cfg:
# sudo grub-mkconfig -o local.grub.cfg

# Amend:
# add menuentry '$DIST_NAME (secure boot)' --unrestricted --class ubuntu --class gnu-linux --class gnu
# ...

# Sign config, vmlinuz, initrd:
# gpg --default-key "$GPG_KEY" --detach-sign /boot/efi/grub.cfg
# gpg --default-key "$GPG_KEY" --detach-sign /boot/efi/vmlinuz-$KERNEL_VERSION
# gpg --default-key "$GPG_KEY" --detach-sign /boot/efi/initrd.img-$KERNEL_VERSION



@dc.dataclass
class GrubRes:
    efi: pl.Path # Path to a stanalone EFI GRUB binary (not signed)
    main_config: FileAndSig # Path to main config and its signature

class Grub:
    MAIN_CFG_BASENAME: str = "grub.cfg"
    EFI_BASENAME: str = "grubx64.efi"

    @staticmethod
    def _create_trampoline_config(dry_run: bool, out_path: pl.Path, pbkdf_grub_pass_path: pl.Path) -> None:
        def get_root_id(dry_run: bool) -> str:
            res: ExecRes = exec(dry_run, 'bash -c "lsblk -f | grep -i efi | grep -E -o \"[A-Z0-9]{4}-[A-Z0-9]{4}\""')
            if res.is_err():
                logger.critical(f"Failed to obtain root efi ID via lsblk: {res}")
            return res.out
        def get_pass_hash_from_file(dry_run: bool, path: pl.Path) -> str:
            if dry_run:
                return "grub.pbkdf2.sha512.10000.2625"
            with open(path) as f:
                pbkdf_grub_pass: str = f.readline()
                if not pbkdf_grub_pass.startswith("grub.pbkdf2.sha512."):
                    logger.critical(f"Something is wrong with your GRUB pbkdf password.")
                return pbkdf_grub_pass

        CORE_GRUB_CFG: str = f"""
set check_signatures=enforce
export check_signatures
set superusers=root
export superusers
password_pbkdf2 root {get_pass_hash_from_file(dry_run=dry_run, path=pbkdf_grub_pass_path)}
search --no-floppy --fs-uuid --set=root {get_root_id(dry_run=dry_run)}
configfile /grub.cfg
echo /{Grub.MAIN_CFG_BASENAME} did not boot the system, rebooting the system in 10 seconds...
sleep 10
reboot
"""
        if not dry_run:
            with open(out_path, "w") as out:
                out.write(CORE_GRUB_CFG)

        logger.info(f'Created grub trampoline config at: {out_path}')


    @staticmethod
    def _create_standalone(dry_run: bool, out_path: pl.Path, trampoline_cfg: FileAndSig, pub_key: pl.Path) -> None:
        # https://www.linux.org/threads/understanding-the-various-grub-modules.11142/
        modules: str = f'efi_gop efi_uga linuxefi all_video archelp boot bufio configfile cpio cpio_be crypto echo ext2 ' \
                       f'extcmd fat font fshelp gcry_dsa gcry_rsa gcry_sha1 gcry_sha512 gettext ' \
                       f'gfxterm gzio linux ls lvm memdisk minicmd mmap mpi normal part_gpt ' \
                       f'part_msdos password_pbkdf2 pbkdf2 procfs reboot relocator search search_fs_file ' \
                       f'search_fs_uuid search_label sleep tar test terminal verifiers video_fb'
        command: str = f'grub-mkstandalone --directory /usr/lib/grub/x86_64-efi ' \
                       f'--format x86_64-efi ' \
                       f'--modules "{modules}" ' \
                       f'--pubkey {pub_key} ' \
                       f'--output {out_path} ' \
                       f'boot/grub/grub.cfg={trampoline_cfg.file} ' \
                       f'boot/grub/grub.cfg.sig={trampoline_cfg.sig}'
        res: ExecRes = ProgPack('grub-mkstandalone', 'grub-common').exec(dry_run, command)
        if res.is_err():
            logger.critical(f'Failed to create_standalone_grub: {command} failed: {res}')
        logger.info(f'Created standalone grub EFI binary at: {out_path}')


    @staticmethod
    def _create_main_config(dry_run: bool, out_path: pl.Path, versions: t.List[KernelVersion]) -> None:
        logger.info(f'Creating main GRUB config for kernels: {versions}...')

        def get_dist_name(dry_run: bool) -> str:
            res: ExecRes = exec(dry_run, f"bash -c 'grep PRETTY_NAME /etc/os-release | cut -d \\\" -f 2'")
            if res.is_err():
                logger.critical(f'Failed to get_pretty_name of the OS: {res}')
            return res.out

        def get_kernel_cmdline(dry_run: bool) -> str:
            res: ExecRes = exec(dry_run, "bash -c \"cat /proc/cmdline | tr -s ' ' | cut -d ' ' -f 2-\"")
            if res.is_err():
                logger.critical(f'Failed to get_kernel_cmdline: {res}')
            return res.out

        def generate_custom_menu_entries(dist: str, cmdline: str, versions: t.List[KernelVersion]) -> str:
            menu_entries: str = ""
            for kver in versions:
                version = kver.to_string()
                logger.info(f'Generating menuentry for kernel version: {version}, cmdline: {cmdline} and OS: {dist}')
                menu_entry: str = f"""
menuentry '{dist} (secure boot)' --unrestricted --class ubuntu --class gnu-linux --class gnu {{
   recordfail
   load_video
   gfxmode $linux_gfx_mode
   insmod gzio
   if [ x$grub_platform = xxen ]; then insmod xzio; insmod lzopio; fi
   linux   /vmlinuz-{version} {cmdline}
   initrd  /initrd.img-{version}
}}
"""
                menu_entries += '\n' + menu_entry
            return menu_entries

        tmp_main_config: pl.Path = out_path.with_suffix(out_path.suffix + ".tmp")
        res: ExecRes = ProgPack('grub-mkconfig', 'grub-common').exec(dry_run, f"grub-mkconfig -o {tmp_main_config}",
                                                                     root_is_required=True)
        if res.is_err():
            logger.critical(f'Failed to create_grub_main_config and/or save it to {tmp_main_config}: {res}')

        menu_entries: str = generate_custom_menu_entries(dist=get_dist_name(dry_run=dry_run),
                                                         cmdline=get_kernel_cmdline(dry_run=dry_run),
                                                         versions=versions)
        if not dry_run:
            with open(tmp_main_config, "r") as reader:
                with open(out_path, "w") as writer:
                    for line in reader:
                        if line.strip().startswith('menuentry ') and menu_entries:
                            writer.write(menu_entries)
                            menu_entries = ""
                        writer.write(line)
            tmp_main_config.unlink()
        logger.info(f'Created main GRUB config at: {out_path}')


    @staticmethod
    def create_standalone_and_config(dry_run: bool,
                                     gpg: Gpg,
                                     work_dir: pl.Path,
                                     pbkdf_grub_pass_path: pl.Path,
                                     versions: t.List[KernelVersion]) -> GrubRes:
        res: GrubRes = GrubRes(efi=work_dir / Grub.EFI_BASENAME,
                               main_config=FileAndSig(work_dir / Grub.MAIN_CFG_BASENAME))

        trampoline_config: FileAndSig = FileAndSig(work_dir / "grub.init.cfg")
        Grub._create_trampoline_config(dry_run=dry_run,
                                       out_path=trampoline_config.file,
                                       pbkdf_grub_pass_path=pbkdf_grub_pass_path)
        verify_1: str = re_sign_file_with_gpg(dry_run, trampoline_config, gpg, do_log=False)
        logger.info(f'Signed grub trampoline config. Signature: {trampoline_config.sig}, '
                    f'you can verify it yourself: {verify_1}')

        pub_key: pl.Path = gpg.export_pub_key(work_dir)
        Grub._create_standalone(dry_run=dry_run,
                                out_path=res.efi,
                                trampoline_cfg=trampoline_config,
                                pub_key=pub_key)

        Grub._create_main_config(dry_run=dry_run, out_path=res.main_config.file, versions=versions)
        verify_2: str = re_sign_file_with_gpg(dry_run, res.main_config, gpg, do_log=False)
        logger.info(f'Signed grub main config. Signature: {res.main_config.sig}, '
                    f'you can verify it yourself: {verify_2}')

        if not dry_run:
            pub_key.unlink() # Cleanup
        return res


class GrubBootResult:
    def __init__(self, boot: pl.Path = pl.Path('/boot')):
        self.boot = boot
    def kernels_dir(self) -> pl.Path:
        return self.boot / "efi"
    def initrds_dir(self) -> pl.Path:
        return self.boot / "efi"
    def grub_full_path(self) -> pl.Path:
        return self.boot / "efi/EFI/ubuntu" / Grub.EFI_BASENAME
    def grub_cfg(self) -> FileAndSig:
        return FileAndSig(self.boot / "efi" / Grub.MAIN_CFG_BASENAME)


MAKE_NEW_GRUB_BOOT_CMD_LINE_OPT: str = "danger/grub/make-new-boot"
def make_new_grub_boot(dry_run: bool,
                       work_dir: pl.Path,
                       backups_dir: pl.Path,
                       boot_dir: pl.Path,
                       wrapped_gpg: WrappedGpg,
                       uefi: UefiEngine,
                       pbkdf_grub_pass_path: pl.Path) -> None:
    make_boot_backup(dry_run, boot_dir=boot_dir, backups_dir=backups_dir)
    if not dry_run:
        work_dir.mkdir(parents=True, exist_ok=True)
    versions: t.List[KernelVersion] = KernelVersion.get_latest(dry_run, 2, boot_dir)

    logger.info(f'Preparing standalone GRUB, its config and signing it with GPG...')
    with wrapped_gpg as gpg:
        grub_res: GrubRes = Grub.create_standalone_and_config(dry_run=dry_run,
                                                              gpg=gpg,
                                                              work_dir=work_dir,
                                                              pbkdf_grub_pass_path=pbkdf_grub_pass_path,
                                                              versions=versions)
    layout: GrubBootResult = GrubBootResult(boot_dir)
    logger.info(f'Coping results to the right place...')
    cmds: t.List[str] = [
        f'cp {grub_res.main_config.file} {layout.grub_cfg().file}',
        f'cp {grub_res.main_config.sig} {layout.grub_cfg().sig}',
        f'cp {grub_res.efi} {layout.grub_full_path()}'
    ]
    for version in versions:
        kernel: pl.Path = boot_dir / version.to_string('vmlinuz-')
        initrd: pl.Path = boot_dir / version.to_string('initrd.img-')
        cmds.append(f'cp {kernel} {layout.kernels_dir()}')
        cmds.append(f'cp {initrd} {layout.initrds_dir()}')
    for cmd in cmds:
        res: ExecRes = exec(dry_run, command=cmd, echo_output=True, root_is_required=True)
        if res.is_err():
            logger.critical(f'Failed to install: {cmd}: {res}')


    logger.info(f'(Re-)signing all EFI binaries with SSL...')
    def get_list_of_kernels_in(dry_run: bool, dir: pl.Path) -> t.List[pl.Path]:
        if dry_run:
            return [dir / KernelVersion(1, 2, 3, 4, "generic").to_string('vmlinuz-')]
        return [dir / x for x in os.listdir(dir) if KernelVersion.matches(x)]
    def get_list_of_EFIs() -> t.List[pl.Path]:
        result: t.List[pl.Path] = []
        for root, subdirs, files in os.walk(boot_dir / "efi"):
            result += [pl.Path(root) / file for file in files if file.lower().endswith('.efi')]
        return result
    for file in get_list_of_kernels_in(dry_run, boot_dir) + \
                get_list_of_kernels_in(dry_run, boot_dir / "efi") + \
                get_list_of_EFIs():
        re_sign_efi_file(dry_run=dry_run, file_to_sign=file, signed_file_path=file, uefi=uefi)

    logger.info(f'(Re-)signing files with GPG...')
    with wrapped_gpg as gpg:
        for version in versions:
            for dir in [boot_dir, boot_dir / "efi"]:
                re_sign_file_with_gpg(dry_run, FileAndSig(dir / version.to_string("vmlinuz-")), gpg)
                re_sign_file_with_gpg(dry_run, FileAndSig(dir / version.to_string("initrd.img-")), gpg)


    # https://askubuntu.com/questions/1333936/why-does-shim-mokmanager-allow-to-circumvent-all-protections-of-secureboot-an
    logger.info(f'Removing backdoor-ish MokManager...')
    rm: ExecRes = exec(dry_run, command=f'rm -f {boot_dir / "efi/EFI/ubuntu/mmx64.efi"}', echo_output=True, root_is_required=True)
    if rm.is_err():
        logger.critical(f'Failed to remove MokManager: {rm}')
    rm: ExecRes = exec(dry_run, command=f'rm -f {boot_dir / "efi/EFI/BOOT/mmx64.efi"}', echo_output=True, root_is_required=True)
    if rm.is_err():
        logger.critical(f'Failed to remove MokManager: {rm}')

























# ==============================================================================================================
# ==============================================================================================================
# EFI Stub + Unified Kernel image


# Install linuxx64.efi.stub
# Source of cmdline
# Disk and partition - command line option? Where EFI is mounted? "sda 1", "/dev/nvme0n1p1"
# Where the list of boot option is stored? How it is modified? What is required in order to modify it?
# Updates, new kernels, images - need to diff installed EFIs and kernels in /boot?

# https://wiki.archlinux.org/title/Systemd-boot#Preparing_a_unified_kernel_image
# https://www.cogitri.dev/posts/04-secure-boot-with-unified-kernel-image/
# objcopy \
#   --add-section .osrel="/etc/os-release" --change-section-vma .osrel=0x20000 \
#   --add-section .cmdline="/proc/cmdline" --change-section-vma .cmdline=0x30000 \
#   --add-section .linux="/boot/linux-lts" --change-section-vma .linux=0x40000 \
#   --add-section .initrd="/tmp/unified-initramfs" --change-section-vma .initrd=0x3000000 \
#   /usr/lib/gummiboot/linuxx64.efi.stub /boot/alpine.efi

# efibootmgr --create --disk /dev/sda     --part 1 --label "Alpine Linux" --loader "\alpine.efi"
# efibootmgr --create --disk /dev/nvme0n1 --part 1 --label "Arch Linux"   --loader /vmlinuz-linux-fsync --unicode 'root=PARTUUID=9a95b925-05f3-fd49-8b08-5e3a466ee3a5 rw initrd=\intel-ucode.img initrd=\initramfs-linux-fsync.img'
# efibootmgr --create                     --part 1 --label MyEFIStubLinux --loader /vmlinuz.efi         --unicode 'initrd=\initrd.img root=/dev/mapper/vgkubuntu-root ro'

class EfiStubBootResult:
    LATEST_BOOTMGR_ENTRY: str = "SecBoot Latest Linux"
    PREV_BOOTMGR_ENTRY: str = "SecBoot Previous Linux"
    LATEST_BASENAME: str = "secboot-linux-latest.efi"
    PREV_BASENAME: str = "secboot-linux-prev.efi"
    _PREFIX: str = "" #"EFI/"

    def __init__(self, boot: pl.Path = pl.Path('/boot')):
        self.boot = boot
    def latest_efi_path(self) -> pl.Path:
        with_prefix: str = EfiStubBootResult._PREFIX + EfiStubBootResult.LATEST_BASENAME
        return self.boot / 'efi' / with_prefix # /boot/efi/secboot-linux-latest.efi
    def prev_efi_path(self) -> pl.Path:
        with_prefix: str = EfiStubBootResult._PREFIX + EfiStubBootResult.PREV_BASENAME
        return self.boot / 'efi' / with_prefix
    @staticmethod
    def latest_from_efi() -> pl.Path:
        with_prefix: str = EfiStubBootResult._PREFIX + EfiStubBootResult.LATEST_BASENAME
        return pl.Path('/') / with_prefix # /secboot-linux-latest.efi
    @staticmethod
    def prev_from_efi() -> pl.Path:
        with_prefix: str = EfiStubBootResult._PREFIX + EfiStubBootResult.PREV_BASENAME
        return pl.Path('/') / with_prefix
    @staticmethod
    def matches_prev_bootentry(line: str) -> bool:
        entry_label: str = re.escape(EfiStubBootResult.PREV_BOOTMGR_ENTRY)
        basename: str = re.escape(EfiStubBootResult.PREV_BASENAME)
        reg = re.compile(f'^Boot0000\\* {entry_label}[ \\t]+HD\\(\\w+,\\w+,\\w+-\\w+-\\w+-\\w+-\\w+,\\w+,\\w+\\)/File\\(\\\\{basename}\\)')
        m = reg.match(line)
        return bool(m)
    @staticmethod
    def matches_latest_bootentry(line: str) -> bool:
        entry_label: str = re.escape(EfiStubBootResult.LATEST_BOOTMGR_ENTRY)
        basename: str = re.escape(EfiStubBootResult.LATEST_BASENAME)
        reg = re.compile(f'^Boot0001\\* {entry_label}[ \\t]+HD\\(\\w+,\\w+,\\w+-\\w+-\\w+-\\w+-\\w+,\\w+,\\w+\\)/File\\(\\\\{basename}\\)')
        m = reg.match(line)
        return bool(m)

class TestEfiStubBootResult(ut.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
    def test_prev_match(self):
        ok: t.List[str] = [
            "Boot0000* SecBoot Previous Linux     HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x80,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2ef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-ac2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-46c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0a0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(X,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            # Same, but with tabs:
            "Boot0000* SecBoot Previous Linux  \t   HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x80,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2ef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0aa0f3d5-2041-4e6c-ac2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0aa0f3d5-2041-46c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0aa0f3d5-041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GPT,0a0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(1,GT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux\t\tHD(X,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-prev.efi)",
        ]
        not_ok: t.List[str] = [
            "Boot0000*  SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prev.efi)",
            "Boot0000 SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux D(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-20-41-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000,sd)/File(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/Fie(\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\efi\secboot-linux-prev.efi)",
            "Boot0000* SecBoot Previous Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-prevXefi)",
        ]
        for o in ok:
            self.assertTrue(EfiStubBootResult.matches_prev_bootentry(o))
        for no in not_ok:
            self.assertFalse(EfiStubBootResult.matches_prev_bootentry(no))
    def test_latest_match(self):
        ok: t.List[str] = [
            "Boot0001* SecBoot Latest Linux     HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x80,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2ef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-ac2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-46c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0a0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(X,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            # Same, but with tabs:
            "Boot0001* SecBoot Latest Linux   \t  HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0001* SecBoot Latest Linux\tHD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)i.n.i.t.r.d.=.\.i.n.i.t.r.d...i.m.g. .r.o.o.t.=./.d.e.v./.m.a.p.p.e.r./.v.g.k.u.b.u.n.t.u.-.r.o.o.t. .r.o. .c.o.n.s.o.l.e.=.t.t.y.0. .c.o.n.s.o.l.e.=.t.t.y.S.0.,.3.8.4.0.0.n.8.",
            "Boot0001* SecBoot Latest Linux\t HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux \tHD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x80,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux \t\t HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2ef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux\tHD(1,GPT,0aa0f3d5-2041-4e6c-ac2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux\t\t\tHD(1,GPT,0aa0f3d5-2041-46c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux\tHD(1,GPT,0aa0f3d5-041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux\tHD(1,GPT,0a0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux\tHD(1,GT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux\tHD(X,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x100000)/File(\secboot-linux-latest.efi)",
        ]
        not_ok: t.List[str] = [
            "Boot0001*  SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latest.efi)",
            "Boot0001 SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux D(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-20-41-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000,sd)/File(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/Fie(\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\efi\secboot-linux-latest.efi)",
            "Boot0001* SecBoot Latest Linux HD(1,GPT,0aa0f3d5-2041-4e6c-acf2-b71bb2eef4a0,0x800,0x10000)/File(\secboot-linux-latestXefi)",
        ]
        for o in ok:
            self.assertTrue(EfiStubBootResult.matches_latest_bootentry(o))
        for no in not_ok:
            self.assertFalse(EfiStubBootResult.matches_latest_bootentry(no))


MAKE_NEW_EFISTUB_BOOT_CMD_LINE_OPT: str = "danger/efistub/make-new-boot"
def make_new_efistub_boot(dry_run: bool,
                          work_dir: pl.Path,
                          backups_dir: pl.Path,
                          boot_dir: pl.Path,
                          disk: str,
                          partition: int,
                          kernel_parameters: str,
                          uefi: UefiEngine) -> None:
    def create_unified_kernel_from(dry_run: bool, boot_dir: pl.Path, version: KernelVersion, out: pl.Path, uefi: UefiEngine) -> None:
        logger.info(f'Creating unified kernel image from vmlinuz and initrd {version.to_string()} in {boot_dir}')
        linuxx64_efi_stub: pl.Path = pl.Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub')
        install_if_file_does_not_exist(dry_run, linuxx64_efi_stub, 'systemd')
        kernel: pl.Path = boot_dir / version.to_string('vmlinuz-')
        initrd: pl.Path = boot_dir / version.to_string('initrd.img-')
        res: ExecRes = ProgPack('objcopy', 'binutils').exec(
            dry_run,
            f'objcopy --add-section .osrel="/etc/os-release" --change-section-vma .osrel=0x20000 '
            f'        --add-section .cmdline="/proc/cmdline" --change-section-vma .cmdline=0x30000 '
            f'        --add-section .linux="{kernel}" --change-section-vma .linux=0x40000 '
            f'        --add-section .initrd="{initrd}" --change-section-vma .initrd=0x3000000 '
            f'{linuxx64_efi_stub} {out}')
        if res.is_err():
            logger.critical(f'Failed to create_unified_kernel_from {kernel}, {initrd} and save it to {out}: {res}')

        re_sign_efi_file(dry_run=dry_run, file_to_sign=out, signed_file_path=out, uefi=uefi)


    def repopulate_efibootmgr_if_needed(dry_run: bool, disk: str, partition: int) -> None:
        entry_regex = re.compile(r'^Boot(?P<g1>[0-9A-F]{4})')
        res: ExecRes = ProgPack('efibootmgr', 'efibootmgr').exec(False, 'efibootmgr -v')
        if res.is_err():
            logger.critical(f'Failed get info from efibootmgr: {res}')
        boot_entries = [line for line in res.out.split('\n') if entry_regex.match(line)]
        need_to_repopulate: bool = False
        if not need_to_repopulate and len(boot_entries) != 2:
            logger.info(f'Need to repopulate efibootmgr entries because number of entries (which is '
                        f'{len(boot_entries)}) is not 2')
            need_to_repopulate = True
        if not need_to_repopulate and not EfiStubBootResult.matches_prev_bootentry(boot_entries[0]):
            logger.info(f'Need to repopulate efibootmgr entries because the first entry ({boot_entries[0]}) does not '
                        f'match expected {EfiStubBootResult.PREV_BOOTMGR_ENTRY}')
            need_to_repopulate = True
        if not need_to_repopulate and not EfiStubBootResult.matches_latest_bootentry(boot_entries[1]):
            logger.info(f'Need to repopulate efibootmgr entries because the second entry ({boot_entries[1]}) does not '
                        f'match expected {EfiStubBootResult.LATEST_BOOTMGR_ENTRY}')
            need_to_repopulate = True

        if need_to_repopulate == False:
            return # Everything is fine

        logger.info(f'Got the following from efibootmgr:\n{res.out}')

        for entry in boot_entries:
            boot_id: str = entry_regex.match(entry).group('g1')
            logger.info(f'Removing boot: {boot_id}')
            res: ExecRes = ProgPack('efibootmgr', 'efibootmgr').exec(dry_run,
                                   f'efibootmgr -B -b {boot_id}', root_is_required=True)
            if res.is_err():
                logger.critical(f'Failed to remove Boot {boot_id}: {res}')

        # Finally, add our own:
        def add_entry(dry_run: bool, disk: str, partition: int, label: str, efi: pl.Path) -> None:
            logger.info(f'Adding boot entry for "{label}", {efi}')
            #            efibootmgr --create --disk /dev/nvme0n1 --part 1 --label "SecBoot Previous Linux" --loader "/secboot-linux-prev.efi" --unicode "BOOT_IMAGE=/vmlinuz-5.11.0-16-generic root=/dev/mapper/vgkubuntu-root ro quiet splash vt.handoff=7 nvidia-drm.modeset=1"
            cmd: str = f'efibootmgr --create --disk {disk} --part {partition} --label "{label}" --loader "{efi}" --unicode "{kernel_parameters}"'
            res: ExecRes = ProgPack('efibootmgr', 'efibootmgr').exec(dry_run, cmd, root_is_required=True)
            if res.is_err():
                logger.critical(f'Failed to add an entry for "{EfiStubBootResult.PREV_BOOTMGR_ENTRY}" with efi at'
                                f'{efi} in efibootmgr: {res}')

        add_entry(dry_run, disk, partition, EfiStubBootResult.PREV_BOOTMGR_ENTRY, EfiStubBootResult.prev_from_efi())
        add_entry(dry_run, disk, partition, EfiStubBootResult.LATEST_BOOTMGR_ENTRY, EfiStubBootResult.latest_from_efi())


    if not dry_run:
        work_dir.mkdir(parents=True, exist_ok=True)
    latest_efi: pl.Path = work_dir / EfiStubBootResult.LATEST_BASENAME
    prev_efi: pl.Path = work_dir / EfiStubBootResult.PREV_BASENAME
    versions: t.List[KernelVersion] = KernelVersion.get_latest(dry_run, 2, boot_dir)
    create_unified_kernel_from(dry_run, boot_dir, versions[0], latest_efi, uefi)
    create_unified_kernel_from(dry_run, boot_dir, versions[min(1, len(versions) - 1)], prev_efi, uefi)

    make_boot_backup(dry_run, boot_dir=boot_dir, backups_dir=backups_dir)
    boot_result: EfiStubBootResult = EfiStubBootResult(boot_dir)
    reinstall_efi_cmds: t.List[str] = [
        f'find {boot_dir / "efi/"} -mindepth 1 ! -name "*.cer" -delete', # Removing everything in efi/, but NOT efi/ itself
        f'mkdir -p {boot_result.prev_efi_path().parent}',
        f'mkdir -p {boot_result.latest_efi_path().parent}',
        f'cp {prev_efi} {boot_result.prev_efi_path()}',
        f'cp {latest_efi} {boot_result.latest_efi_path()}'
    ]
    for cmd in reinstall_efi_cmds:
        res: ExecRes = exec(dry_run, command=cmd, echo_output=True, root_is_required=True)
        if res.is_err():
            logger.critical(f'Failed to install: {cmd}: {res}')

    repopulate_efibootmgr_if_needed(dry_run, disk, partition)



























# ==============================================================================================================
# ==============================================================================================================
# Examples

BACKUP_CERTS_FROM_UEFI_EXAMPLE: str          = f'./secboot.py --log-level INFO {BACKUP_CERTS_FROM_UEFI_CMD_LINE_OPT} -o sec_out/'

GENERATE_GPG_KEYS_EXAMPLE: str               = f'./secboot.py --log-level INFO {GENERATE_GPG_KEYS_CMD_LINE_OPT} --GNUPGHOME sec_out/gpg --id Popl --gpg/pass ""'
GENERATE_UEFI_KEYS_EXAMPLE: str              = f'./secboot.py --log-level INFO {GENERATE_UEFI_KEYS_CMD_LINE_OPT} -o sec_out/ --id Popl'

ENROLL_SSL_TO_YUBIKEY_EXAMPLE: str           = f'./secboot.py --log-level INFO {ENROLL_SSL_TO_YUBIKEY_CMD_LINE_OPT} --keys-dir sec_out/ --uefi/nfc-reader "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL"'
ENROLL_SSL_TO_UEFI_EXAMPLE_FS: str           = f'./secboot.py --log-level INFO {ENROLL_SSL_TO_UEFI_CMD_LINE_OPT} --uefi/engine fs --uefi/keys-dir sec_out/'
ENROLL_SSL_TO_UEFI_EXAMPLE_YUBIKEY: str      = f'./secboot.py --log-level INFO {ENROLL_SSL_TO_UEFI_CMD_LINE_OPT} --uefi/engine yu --uefi/nfc-reader "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL"'

RE_SIGN_EFI_FILE_EXAMPLE_FS: str             = f'./secboot.py --log-level INFO {RE_SIGN_EFI_FILE_CMD_LINE_OPT} --file-to-sign sec_out/shimx64.efi.signed --uefi/engine fs --uefi/keys-dir sec_out/'
RE_SIGN_EFI_FILE_EXAMPLE_YUBIKEY: str        = f'./secboot.py --log-level INFO {RE_SIGN_EFI_FILE_CMD_LINE_OPT} --file-to-sign sec_out/shimx64.efi.signed --uefi/engine yu --uefi/nfc-reader "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL"'

RE_SIGN_FILE_WITH_GPG_EXAMPLE_YUBIKEY: str   = f'./secboot.py --log-level INFO {RE_SIGN_FILE_WITH_GPG_CMD_LINE_OPT} --file-to-sign sec_out/shimx64.efi --gpg/engine yu --gpg/pub-key ~/devel/gpg*'
RE_SIGN_FILE_WITH_GPG_EXAMPLE_FS: str        = f'./secboot.py --log-level INFO {RE_SIGN_FILE_WITH_GPG_CMD_LINE_OPT} --file-to-sign sec_out/shimx64.efi --gpg/engine fs --gpg/key-id ADDB2... --GNUPGHOME sec_out/gpg'

MAKE_NEW_GRUB_BOOT_EXAMPLE_FS: str           = f'./secboot.py --log-level INFO {MAKE_NEW_GRUB_BOOT_CMD_LINE_OPT} --boot-dir /boot --uefi/engine fs --uefi/keys-dir sec_out/ --gpg/engine fs --gpg/key-id ADDB2... --GNUPGHOME sec_out/gpg --gpg/pass "" --pbkdf-grub-pass-path ~/grub_pbkdf2_pass'
MAKE_NEW_GRUB_BOOT_EXAMPLE_YUBIKEY: str      = f'./secboot.py --log-level INFO {MAKE_NEW_GRUB_BOOT_CMD_LINE_OPT} --boot-dir /boot --uefi/engine yu --uefi/nfc-reader "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL" --gpg/engine yu --gpg/pub-key ~/devel/gpg* --pbkdf-grub-pass-path ~/grub_pbkdf2_pass'

MAKE_NEW_EFISTUB_BOOT_EXAMPLE_FS: str        = f'./secboot.py --log-level INFO {MAKE_NEW_EFISTUB_BOOT_CMD_LINE_OPT} --boot-dir /boot --disk /dev/nvme0n1 --partition 1 --kernel-parameters "BOOT_IMAGE=/vmlinuz-5.11.0-16-generic root=/dev/mapper/vgkubuntu-root ro quiet splash vt.handoff=7 nvidia-drm.modeset=1" --uefi/engine fs --uefi/keys-dir sec_out/'
MAKE_NEW_EFISTUB_BOOT_EXAMPLE_YUBIKEY: str   = f'./secboot.py --log-level INFO {MAKE_NEW_EFISTUB_BOOT_CMD_LINE_OPT} --boot-dir /boot --disk /dev/nvme0n1 --partition 1 --kernel-parameters "BOOT_IMAGE=/vmlinuz-5.11.0-16-generic root=/dev/mapper/vgkubuntu-root ro quiet splash vt.handoff=7 nvidia-drm.modeset=1" --uefi/engine yu --uefi/nfc-reader "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL"'


QEMU_INITIALISE_EFISTUB_CMD_LINE_OPT: str = "qemu/efistub/initialise"
QEMU_RUN_EFISTUB_TESTS_CMD_LINE_OPT: str  = "qemu/efistub/run-tests"
QEMU_INITIALISE_EFISTUB_EXAMPLE: str      = f'./secboot.py --log-level INFO {QEMU_INITIALISE_EFISTUB_CMD_LINE_OPT} --vm-dir ~/devel/secboot_efistub_testing'
QEMU_RUN_EFISTUB_TESTS_EXAMPLE: str       = f'./secboot.py --log-level INFO {QEMU_RUN_EFISTUB_TESTS_CMD_LINE_OPT} --vm-dir ~/devel/secboot_efistub_testing'
QEMU_INITIALISE_GRUB_CMD_LINE_OPT: str = "qemu/grub/initialise"
QEMU_RUN_GRUB_TESTS_CMD_LINE_OPT: str  = "qemu/grub/run-tests"
QEMU_INITIALISE_GRUB_EXAMPLE: str      = f'./secboot.py --log-level INFO {QEMU_INITIALISE_GRUB_CMD_LINE_OPT} --vm-dir ~/devel/secboot_grub_testing'
QEMU_RUN_GRUB_TESTS_EXAMPLE: str       = f'./secboot.py --log-level INFO {QEMU_RUN_GRUB_TESTS_CMD_LINE_OPT} --vm-dir ~/devel/secboot_grub_testing'


















# ==============================================================================================================
# ==============================================================================================================
# QEMU Tests

@dc.dataclass()
class QemuImage:
    image: pl.Path
    uefi: pl.Path

    @staticmethod
    def new(vm_dir: pl.Path) -> 'QemuImage':
        return QemuImage(image=vm_dir / "with-secboot.img", uefi=vm_dir / "OVMF-with-secboot.fd")
    @staticmethod
    def orig(vm_dir: pl.Path) -> 'QemuImage':
        return QemuImage(image=vm_dir / "without-secboot.img", uefi=vm_dir / "OVMF-without-secboot.fd")
    @staticmethod
    def SYS_UEFI() -> pl.Path:
        return pl.Path("/usr/share/ovmf/OVMF.fd")

    def recreate_new_snapshot(self, dry_run: bool, new: 'QemuImage') -> None:
        import stat
        os.chmod(self.image, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        os.chmod(self.uefi, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        logger.info(f'Removed write permissions from {self.image} and {self.uefi}')

        safe_rm(dry_run, new.uefi) # Being idempotent
        res_2: ExecRes = exec(dry_run, f'cp {self.uefi} {new.uefi}')
        if res_2.is_err():
            logger.critical(f'Failed to cp {self.uefi} to {new.uefi}: {res_2}')
        if not dry_run:
            os.chmod(new.uefi, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR | stat.S_IWGRP)

        # qemu-img create -f qcow2 -b sb-image.img trying_to_flip_a_bit.img
        #
        res: ExecRes = ProgPack('qemu-img', 'qemu-utils').exec(dry_run,
                                                               f'qemu-img create -f qcow2 -b {self.image} {new.image}')
        if res.is_err():
            logger.critical(f'Failed to make a snapshot of {self.image} in {new.image}: {res}')
        logger.info(f"Created new snapshot {new} from {self} and made the latter immutable")


# ==================================================================================================================================
# Uefi failure to load a bootloader looks like this (caused by failed signature checks / wrong SSL certificates):

# In case of shim:
# BdsDxe: loading Boot0006 "ubuntu" from HD(1,GPT,D244B70F-38D8-4330-86AE-7387F52E23BD,0x800,0x100000)/\EFI\ubuntu\shimx64.efi
# BdsDxe: failed to load Boot0006 "ubuntu" from HD(1,GPT,D244B70F-38D8-4330-86AE-7387F52E23BD,0x800,0x100000)/\EFI\ubuntu\shimx64.efi: Access Denied
# BdsDxe: failed to load Boot0001 "UEFI QEMU DVD-ROM QM00003 " from PciRoot(0x0)/Pci(0x1,0x1)/Ata(Secondary,Master,0x0): Not Found
# BdsDxe: loading Boot0002 "UEFI QEMU HARDDISK QM00001 " from PciRoot(0x0)/Pci(0x1,0x1)/Ata(Primary,Master,0x0)
# BdsDxe: failed to load Boot0002 "UEFI QEMU HARDDISK QM00001 " from PciRoot(0x0)/Pci(0x1,0x1)/Ata(Primary,Master,0x0): Access Denied
#
# >>Start PXE over IPv4.
# PXE-E16: No valid offer received.
# BdsDxe: failed to load Boot0003 "UEFI PXEv4 (MAC:525400123456)" from PciRoot(0x0)/Pci(0x3,0x0)/MAC(525400123456,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0): Not Found
#

# In case of Unified kernel image:
# BdsDxe: loading Boot0001 "SecBoot Latest Linux" from HD(1,GPT,0AA0F3D5-2041-4E6C-ACF2-B71BB2EEF4A0,0x800,0x100000)/\secboot-linux-latest.efi
# BdsDxe: failed to load Boot0001 "SecBoot Latest Linux" from HD(1,GPT,0AA0F3D5-2041-4E6C-ACF2-B71BB2EEF4A0,0x800,0x100000)/\secboot-linux-latest.efi: Access Denied
# BdsDxe: loading Boot0000 "SecBoot Previous Linux" from HD(1,GPT,0AA0F3D5-2041-4E6C-ACF2-B71BB2EEF4A0,0x800,0x100000)/\secboot-linux-prev.efi
# BdsDxe: failed to load Boot0000 "SecBoot Previous Linux" from HD(1,GPT,0AA0F3D5-2041-4E6C-ACF2-B71BB2EEF4A0,0x800,0x100000)/\secboot-linux-prev.efi: Access Denied
# BdsDxe: failed to load Boot0003 "UEFI QEMU DVD-ROM QM00003 " from PciRoot(0x0)/Pci(0x1,0x1)/Ata(Secondary,Master,0x0): Not Found
# BdsDxe: failed to load Boot0004 "UEFI QEMU HARDDISK QM00001 " from PciRoot(0x0)/Pci(0x1,0x1)/Ata(Primary,Master,0x0): Not Found
#
# >>Start PXE over IPv4.
#




# ==================================================================================================================================
# Shim failure to load GRUB looks like this (caused by GRUB tampering):

# ERROR
# Verification failed: (0x1A) Security Violation



# ==================================================================================================================================
# GRUB failure to initialise (read and execute its own configs) looks like this (caused by GRUB config/signature tampering):

# BdsDxe: loading Boot0006 "ubuntu" from HD(1,GPT,D244B70F-38D8-4330-86AE-7387F52E23BD,0x800,0x100000)/\EFI\ubuntu\shimx64.efi
# BdsDxe: starting Boot0006 "ubuntu" from HD(1,GPT,D244B70F-38D8-4330-86AE-7387F52E23BD,0x800,0x100000)/\EFI\ubuntu\shimx64.efi
# /grub.cfg did not boot the system, rebooting the system in 10 seconds...



# ==================================================================================================================================
# GRUB failure to load linux kernel looks like this (caused by vmlinuz tampering):

# error: bad signature.
# error: you need to load the kernel first.
#
# Press any key to continue...


class BootStatuses(Enum):
    Ok = 1
    UefiFailedToLoadShim = 2 # Corresponds to BdsDxe: failed to load Boot0006 "ubuntu" from
                             # HD(1,GPT,D244B70F-38D8-4330-86AE-7387F52E23BD,0x800,0x100000)/\EFI\ubuntu\shimx64.efi:
                             # Access Denied
    UefiFailedToLoadPrevKernel = 3 # Corresponds to BdsDxe: BdsDxe: loading Boot0000 "SecBoot Previous Linux" from
                                   # HD(1,GPT,0AA0F3D5-2041-4E6C-ACF2-B71BB2EEF4A0,0x800,0x100000)/\secboot-linux-prev.efi
    ShimFailedToLoadGrub = 4
    GrubFailedToLoadCfg = 5 # Corresponds to grub.cfg did not boot the system
    GrubFailedToLoadKernelOrInitrd = 6


class Qemu:
    USER: str = 'test'
    PASS: str = 'test'
    USER_PROMPT: str = "test@test-.*\\$"
    ROOT_PROMPT: str = "root@test-.*#"
    HOME: pl.Path = pl.Path(f'/home/{USER}')

    def __init__(self, dry_run: bool, image: QemuImage):
        self.dry_run = dry_run
        self.image = image

    def exec_and_wait(self, req: str, resp: str = USER_PROMPT, use_regex: bool = True, wait_for_echo: bool = True) -> str:
        if self.dry_run:
            return ""

        self.child.send(req) # "Type" command and wait until it appears on the screen
        if wait_for_echo:
            cmd_index = self.child.expect_exact([pexpect.EOF, pexpect.TIMEOUT, req], timeout=10)
            if cmd_index == 0:
                return ""
            assert cmd_index == 2

        self.child.send("\n") # "Hit" Enter

        index = None
        while index != 0:
            if use_regex:
                index = self.child.expect([pexpect.EOF, pexpect.TIMEOUT, resp], timeout=0.1)
            else:
                index = self.child.expect_exact([pexpect.EOF, pexpect.TIMEOUT, resp], timeout=0.1)
            if index == 2:
                return self.child.before.decode("utf-8") + self.child.after.decode("utf-8")
        return ""

    def hang(self) -> None:
        if self.dry_run:
            return

        # counter: int = 0
        index = None
        while index != 0:
            # counter += 1
            index = self.child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=0.1)



    # Waits for any or reqresps[*][0] strings in the output and sends text from reqresps[x][1] if there is a match
    # Returns awaited/encountered string or None, if Qemu exited
    def wait_and_exec(self, reqresps: t.List[t.Tuple[str, t.Union[str, None]]], use_regex: bool = True) -> t.Union[None, str]:
        if self.dry_run:
            return ""

        index = None
        reqs: t.List[str] = [elem[0] for elem in reqresps]
        while index != 0:
            if use_regex:
                index = self.child.expect([pexpect.EOF, pexpect.TIMEOUT] + reqs, timeout=0.1)
            else:
                index = self.child.expect_exact([pexpect.EOF, pexpect.TIMEOUT] + reqs, timeout=0.1)
            if index >= 2:
                resp: t.Union[str, None] = reqresps[index - 2][1]
                if resp is not None:
                    self.child.sendline(resp)
                return reqresps[index - 2][0]
        return None

    def start(self) -> BootStatuses:
        cmd: str = f'qemu-system-x86_64 -m 3G -drive file={self.image.uefi},format=raw,if=pflash -enable-kvm -smp 2 ' \
                   f'-net nic -net user -object rng-random,id=rng0,filename=/dev/urandom ' \
                   f'-device virtio-rng-pci,rng=rng0 -serial stdio -hda {self.image.image}'
        logger.debug(f'{"NOT " if self.dry_run else ""}executing: {cmd}')
        if self.dry_run:
            return BootStatuses.Ok
        for i in range(100):
            print() # Qemu clears screen, ensure it does not erase log messages
        self.child = pexpect.spawn(cmd) #, logfile=sys.stdout.buffer)
        self.child.logfile_read = sys.stdout.buffer

        disk_unlocked: bool = False
        DISK_UNLOCK_STR: str = "Please unlock disk "
        UEFI_FAILURE_TO_LOAD_SHIM_STR: str = "BdsDxe: failed to load.*\\\\shimx64\.efi: Access Denied"
        UEFI_FAILURE_TO_LOAD_PREV_KERNEL_STR: str = f'BdsDxe: failed to load Boot0000 ' \
                                                    f'"{EfiStubBootResult.PREV_BOOTMGR_ENTRY}" from HD\\(.*\\)/\\\\secboot-linux-prev\.efi: Access Denied'
        SHIM_FILURE_TO_LOAD_FRUB_STR: str = "Verification failed: \\(0x1A\\) Security Violation"
        GRUB_FAILURE_TO_LOAD_CFG_STR: str = "\\/grub\\.cfg did not boot the system, rebooting the system in 10 seconds\\.\\.\\."
        out = self.wait_and_exec([("The highlighted entry will be executed automatically in", ''),
                                  (DISK_UNLOCK_STR, Qemu.PASS), # In case there is no GRUB (=> no prompt)
                                  (UEFI_FAILURE_TO_LOAD_SHIM_STR, None),
                                  (UEFI_FAILURE_TO_LOAD_PREV_KERNEL_STR, None),
                                  (GRUB_FAILURE_TO_LOAD_CFG_STR, None),
                                  (SHIM_FILURE_TO_LOAD_FRUB_STR, None)])
        if out == UEFI_FAILURE_TO_LOAD_SHIM_STR:
            self.child.terminate()
            print(f'\n\nUEFI failure detected')
            return BootStatuses.UefiFailedToLoadShim
        if out == UEFI_FAILURE_TO_LOAD_PREV_KERNEL_STR:
            self.child.terminate()
            print(f'\n\nUEFI failure detected')
            return BootStatuses.UefiFailedToLoadPrevKernel
        elif out == SHIM_FILURE_TO_LOAD_FRUB_STR:
            self.child.terminate()
            print(f'\n\nSHIM failure detected')
            return BootStatuses.ShimFailedToLoadGrub
        elif out == GRUB_FAILURE_TO_LOAD_CFG_STR:
            self.child.terminate()
            print(f'\n\nGRUB config failure detected')
            return BootStatuses.GrubFailedToLoadCfg
        elif out == DISK_UNLOCK_STR:
            disk_unlocked = True

        if disk_unlocked == False:
            GRUB_KERNEL_FAILURE_STR: str = "error: bad signature\\."
            out = self.wait_and_exec([(DISK_UNLOCK_STR, Qemu.PASS),
                                      (GRUB_KERNEL_FAILURE_STR, None)])
            if out == GRUB_KERNEL_FAILURE_STR:
                self.child.terminate()
                print(f'\n\nGRUB kernel load failure detected')
                return BootStatuses.GrubFailedToLoadKernelOrInitrd

        self.wait_and_exec([("test-.* login:", Qemu.USER)])
        self.wait_and_exec([("Password:", Qemu.PASS)])
        self.wait_and_exec([(Qemu.USER_PROMPT, '')])
        time.sleep(2) # Let it finish init/start, otherwise there can be hangs and slow-downs during shutdown
        return BootStatuses.Ok

    def copy(self, src: pl.Path, dst: pl.Path) -> None:
        if self.dry_run:
            return

        import stat
        import base64
        from functools import partial

        with open(src, 'rb') as r:
            # https://docs.python.org/3/library/functions.html#iter
            # Ensure we do not exceed getconf ARG_MAX, which is 2MiB (2097152)
            first: bool = True
            for block in iter(partial(r.read, 32*1024), b''):
                text = base64.b64encode(block).decode('ascii')
                cmd: str = f'echo "{text}" | base64 -d {">" if first else ">>"} {dst}'
                first = False
                self.exec_and_wait(cmd)
        src_stat = os.stat(src)
        if src_stat.st_mode & stat.S_IXUSR and src_stat.st_mode & stat.S_IXGRP and src_stat.st_mode & stat.S_IXOTH:
            self.exec_and_wait(f'chmod +x {dst}')

    def disable_sudo_pass(self) -> None:
        self.exec_and_wait(f'echo "{Qemu.USER} ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers',
                           f'[sudo] password for {Qemu.USER}:', use_regex=False)
        self.exec_and_wait(f'{Qemu.PASS}', wait_for_echo=False)

    def shutdown(self) -> None:
        if self.dry_run:
            return
        self.exec_and_wait(f'sudo shutdown now')
        self.child.wait()

    def overwrite_middle_of(self, file: pl.Path, val: str = "\\x56") -> None:
        self.exec_and_wait(f'sudo su', Qemu.ROOT_PROMPT)
        self.exec_and_wait(f'set -x', Qemu.ROOT_PROMPT)
        self.exec_and_wait(f'cp -f {file} {file}.bak', Qemu.ROOT_PROMPT)
        self.exec_and_wait(f'printf "{val}" | dd of={file} bs=1 seek=`echo "$(stat --printf=%s {file}) / 2" | bc` count=1 conv=notrunc;',
                           Qemu.ROOT_PROMPT)
        self.exec_and_wait(f'cmp -b -c {file} {file}.bak; md5sum {file} {file}.bak', Qemu.ROOT_PROMPT)
        self.exec_and_wait(f'exit')

    def get_str_kernel_version(self) -> str:
        out = self.exec_and_wait('uname -r') if not self.dry_run else "1.2.3-4-generic"
        for s in out.split():
            if KernelVersion.matches(basename=s, with_prefix=False):
                str_kernel_ver: str = s
        if not str_kernel_ver:
            logger.critical(f'Failed to psrse kernel version from uname -r output: {out}')
        return str_kernel_ver


def guide_user_through_vm_creation(dry_run: bool, orig: QemuImage) -> None:
    install_if_file_does_not_exist(dry_run=dry_run, file=QemuImage.SYS_UEFI(), package='ovmf')
    res_1: ExecRes = exec(dry_run, f'cp -f {QemuImage.SYS_UEFI()} {orig.uefi}')
    if res_1.is_err():
        logger.critical(f'Failed to cp {QemuImage.SYS_UEFI()} to {orig.uefi}: {res_1}')

    print(f'You should install OS in VM:')
    print(f'  - Create disk: qemu-img create -f qcow2 {orig.image} 20G')
    print(f'  - Start installer: qemu-system-x86_64 -m 3G -drive file={orig.uefi},format=raw,if=pflash '
          f'-boot d -enable-kvm -smp 2 -net nic -net user -cdrom ~/Downloads/kubuntu-20.10-desktop-amd64.iso '
          f'-hda {orig.image}')
    print(f'  - Create user "test" with password "test"')
    print()
    print(f'Make the VM interactable from host console:')
    print(f'  - sudo nano /etc/default/grub')
    print(f'    # GRUB_TIMEOUT_STYLE=hidden')
    print(f'    GRUB_TIMEOUT=3')
    print(f'    GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,38400n8"')
    print(f'    GRUB_TERMINAL=serial')
    print(f'    GRUB_SERIAL_COMMAND="serial --speed=38400 --unit=0 --word=8 --parity=no --stop=1"')
    print(f'  - Re-generate grub.cfg: grub-mkconfig -o /boot/grub/grub.cfg')
    print()
    print(f'Shutdown the OS')
    print()
    if not dry_run:
        input('Press any key when ready...')

    if not dry_run and orig.image.exists() == False:
        logger.critical(f'{orig.image} does not exist')
    if not dry_run and orig.uefi.exists() == False:
        logger.critical(f'{orig.uefi} does not exist')


def guide_user_through_enrolling_certificates(dry_run: bool, new: QemuImage) -> None:
    while True:
        print('\n\n')
        print(f'Now you have to enroll new keys in UEFI:')
        print(f'  - press and hold <Esc> to enter UEFI settings')
        print(f'  - Device Manager')
        print(f'  - Secure Boot configuration')
        print(f'  - Secure Boot Mode -> Custom Mode')
        print(f'  - Custom Secure Boot Options')
        print(f'  - DB Options -> Enroll Signature -> Enter -> db.cer -> Commit changes and exit')
        print(f'  - Repeat for KEK')
        print(f'  - Repeat for PK')
        print(f'  - Esc -> Esc -> Esc -> On the main menu: Reset')
        print('\n')
        if not dry_run:
            input('Press any key when you are ready...')
        qemu: Qemu = Qemu(dry_run, new)
        status: BootStatuses = qemu.start()
        if status != BootStatuses.Ok:
            logger.critical(f'Failed to boot, something went wrong: {status}')

        out = qemu.exec_and_wait("mokutil --sb-state")
        if "SecureBoot enabled" in out or dry_run:
            qemu.shutdown()
            logger.info(f'SecureBoot has been successfully enabled. Everything works fine. Shuttig down...')
            break
        else:
            logger.info(f'You failed to enroll keys, try again...{len(out)}: {out}')


def qemu_grub_initialise(dry_run: bool, vm_dir: pl.Path) -> None:
    def create_new_boot_in_fresh_vm(dry_run: bool, image: QemuImage) -> None:
        script: pl.Path = Qemu.HOME / pl.Path(__file__).name
        gpg_keyid_regex = re.compile(r".*Generated primary .* with keyid: (?P<g1>\w+).*", re.MULTILINE | re.DOTALL)
        qemu: Qemu = Qemu(dry_run, image)
        qemu.start()
        qemu.disable_sudo_pass()
        qemu.exec_and_wait(f'sudo apt-get -y remove unattended-upgrades') # remove race condition between us and system
        qemu.copy(pl.Path(__file__).resolve(), script) # Copy the script in the VM

        qemu.exec_and_wait(f'sudo {GENERATE_UEFI_KEYS_EXAMPLE} && sudo cp -r ./sec_out/*.cer /boot/efi')
        gpg_gen_out: str = qemu.exec_and_wait(f'sudo {GENERATE_GPG_KEYS_EXAMPLE}')
        gpg_keyid: str = gpg_keyid_regex.match(gpg_gen_out).group('g1') if not dry_run else ""
        qemu.exec_and_wait(req=f'grub-mkpasswd-pbkdf2 | tee ~/grub_pbkdf2_pass_out && cat ~/grub_pbkdf2_pass_out | '
                               f'grep "PBKDF2 hash of your password is" | sed \'s/PBKDF2 hash of your password is //g\' > '
                               f'~/grub_pbkdf2_pass', resp="Enter password:", use_regex=False)
        qemu.exec_and_wait('test', resp="Reenter password:", use_regex=False, wait_for_echo=False) # Our grub password
        qemu.exec_and_wait('test', wait_for_echo=False) # Repeat it

        make_new_boot_cmd: str = MAKE_NEW_GRUB_BOOT_EXAMPLE_FS
        make_new_boot_cmd = make_new_boot_cmd.replace("--gpg/key-id ADDB2...", f"--gpg/key-id {gpg_keyid}")
        qemu.exec_and_wait(f'sudo {make_new_boot_cmd}')

        qemu.shutdown()


    if not dry_run:
        vm_dir.mkdir(parents=True, exist_ok=True)
    orig: QemuImage = QemuImage.orig(vm_dir)
    new: QemuImage = QemuImage.new(vm_dir)
    guide_user_through_vm_creation(dry_run, orig)
    orig.recreate_new_snapshot(dry_run, new)
    create_new_boot_in_fresh_vm(dry_run, new)
    guide_user_through_enrolling_certificates(dry_run, new)

    # qemu-system-x86_64 -m 3G -drive file=/home/dimanne/devel/secboot_testing/OVMF-with-secboot.fd,format=raw,if=pflash
    # -enable-kvm -smp 2 -net nic -net user -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0
    # -serial stdio -hda /home/dimanne/devel/secboot_testing/with-secboot.img



def qemu_efistub_initialise(dry_run: bool, vm_dir: pl.Path) -> None:
    def create_new_boot_in_fresh_vm(dry_run: bool, image: QemuImage) -> None:
        script: pl.Path = Qemu.HOME / pl.Path(__file__).name
        qemu: Qemu = Qemu(dry_run, image)
        qemu.start()
        qemu.disable_sudo_pass()
        qemu.exec_and_wait(f'sudo apt-get -y remove unattended-upgrades') # remove race condition between us and system
        qemu.copy(pl.Path(__file__).resolve(), script) # Copy the script in the VM

        qemu.exec_and_wait(f'sudo {GENERATE_UEFI_KEYS_EXAMPLE} && sudo cp -r ./sec_out/*.cer /boot/efi')

        make_new_boot_cmd: str = MAKE_NEW_EFISTUB_BOOT_EXAMPLE_FS
        make_new_boot_cmd = make_new_boot_cmd.replace("--disk /dev/nvme0n1", f"--disk /dev/sda")
        qemu.exec_and_wait(f'sudo {make_new_boot_cmd}')

        qemu.shutdown()


    if not dry_run:
        vm_dir.mkdir(parents=True, exist_ok=True)
    orig: QemuImage = QemuImage.orig(vm_dir)
    new: QemuImage = QemuImage.new(vm_dir)
    guide_user_through_vm_creation(dry_run, orig)
    orig.recreate_new_snapshot(dry_run, new)
    create_new_boot_in_fresh_vm(dry_run, new)
    guide_user_through_enrolling_certificates(dry_run, new)



class QemuTestingEnv:
    def __init__(self, dry_run: bool, vm_dir: pl.Path):
        self.dry_run = dry_run
        self.vm_dir = vm_dir

    def __enter__(self) -> t.Tuple[QemuImage, pl.Path]:
        if not self.dry_run:
            self.tmp_dir = pl.Path(tempf.mkdtemp(prefix="secboot_qemu_", dir=self.vm_dir))
        else:
            self.tmp_dir = pl.Path(self.vm_dir / "secboot_quem_dry_run")
        base: QemuImage = QemuImage.new(self.vm_dir)

        tampering: QemuImage = QemuImage(image=self.tmp_dir / "tampering.img",
                                         uefi=self.tmp_dir / "OVMF-with-secboot.fd")
        base.recreate_new_snapshot(self.dry_run, tampering)
        orig: QemuImage = QemuImage.orig(self.vm_dir)
        uefi_without_secboot: pl.Path = self.tmp_dir / "OVMF-without-secboot.fd"
        exec(dry_run=self.dry_run, command=f'cp {orig.uefi} {uefi_without_secboot}')
        import stat
        if not self.dry_run:
            os.chmod(uefi_without_secboot, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR | stat.S_IWGRP)

        return (tampering, uefi_without_secboot) # Temp image for tampering and copy of initial UEFI image

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.dry_run:
            safe_rm_dir(self.dry_run, self.tmp_dir)



def qemu_efistub_test_tamper_with_unified_kernel(dry_run: bool, disposable: QemuImage, orig_uefi: pl.Path) -> None:
    qemu: Qemu = Qemu(dry_run, disposable)
    assert qemu.start() == BootStatuses.Ok
    qemu.overwrite_middle_of(file=EfiStubBootResult().latest_efi_path())
    qemu.overwrite_middle_of(file=EfiStubBootResult().prev_efi_path())
    qemu.shutdown()
    if not dry_run:
        assert qemu.start() == BootStatuses.UefiFailedToLoadPrevKernel

def qemu_efistub_run_tests(dry_run: bool, vm_dir: pl.Path) -> None:
    with QemuTestingEnv(dry_run, vm_dir) as image_and_uefi:
        qemu_efistub_test_tamper_with_unified_kernel(dry_run, image_and_uefi[0], image_and_uefi[1])
    logger.info(f'qemu_efistub_test_tamper_with_unified_kernel')



def qemu_grub_test_tamper_with_shim(dry_run: bool, disposable: QemuImage, orig_uefi: pl.Path) -> None:
    qemu: Qemu = Qemu(dry_run, disposable)
    assert qemu.start() == BootStatuses.Ok
    qemu.overwrite_middle_of(file=pl.Path("/boot/efi/EFI/BOOT/BOOTX64.EFI"))
    qemu.overwrite_middle_of(file=pl.Path("/boot/efi/EFI/ubuntu/shimx64.efi"))
    qemu.shutdown()
    if not dry_run:
        assert qemu.start() == BootStatuses.UefiFailedToLoadShim
    # Check that OS failed to boot not because we broke its binaries by writing garbage into them, but
    # because of signature verification. We do it, by trying to boot the same OS with initial UEFI (without keys):
    qemu: Qemu = Qemu(dry_run, QemuImage(image=disposable.image, uefi=orig_uefi))
    if not dry_run:
        assert qemu.start() == BootStatuses.Ok

def qemu_grub_test_tamper_with_grub(dry_run: bool, disposable: QemuImage, orig_uefi: pl.Path) -> None:
    qemu: Qemu = Qemu(dry_run, disposable)
    assert qemu.start() == BootStatuses.Ok
    qemu.overwrite_middle_of(file=GrubBootResult().grub_full_path())
    qemu.shutdown()
    if not dry_run:
        assert qemu.start() == BootStatuses.ShimFailedToLoadGrub
    # Check that OS failed to boot not because we broke its binaries by writing garbage into them, but
    # because of signature verification. We do it, by trying to boot the same OS with initial UEFI (without keys):
    qemu: Qemu = Qemu(dry_run, QemuImage(image=disposable.image, uefi=orig_uefi))
    if not dry_run:
        assert qemu.start() == BootStatuses.Ok

def qemu_grub_test_tamper_with_grub_cfg(dry_run: bool, disposable: QemuImage, orig_uefi: pl.Path) -> None:
    qemu: Qemu = Qemu(dry_run, disposable)
    assert qemu.start() == BootStatuses.Ok
    # Add one empty line at the end of the file
    qemu.exec_and_wait(f'echo "" | sudo tee -a {GrubBootResult().grub_cfg().file}')
    qemu.shutdown()
    if not dry_run:
        assert qemu.start() == BootStatuses.GrubFailedToLoadCfg

def qemu_grub_test_tamper_with_grub_cfg_sig(dry_run: bool, disposable: QemuImage, orig_uefi: pl.Path) -> None:
    qemu: Qemu = Qemu(dry_run, disposable)
    assert qemu.start() == BootStatuses.Ok
    qemu.overwrite_middle_of(file=GrubBootResult().grub_cfg().sig)
    qemu.shutdown()
    if not dry_run:
        assert qemu.start() == BootStatuses.GrubFailedToLoadCfg

def qemu_grub_test_tamper_with_kernel(dry_run: bool, disposable: QemuImage, orig_uefi: pl.Path) -> None:
    qemu: Qemu = Qemu(dry_run, disposable)
    assert qemu.start() == BootStatuses.Ok
    kernel: str = f'vmlinuz-{qemu.get_str_kernel_version()}'
    qemu.overwrite_middle_of(file=GrubBootResult().kernels_dir() / kernel)
    qemu.shutdown()
    if not dry_run:
        assert qemu.start() == BootStatuses.GrubFailedToLoadKernelOrInitrd

def qemu_grub_test_tamper_with_initrd(dry_run: bool, disposable: QemuImage, orig_uefi: pl.Path) -> None:
    qemu: Qemu = Qemu(dry_run, disposable)
    assert qemu.start() == BootStatuses.Ok
    initrd: str = f'initrd.img-{qemu.get_str_kernel_version()}'
    qemu.overwrite_middle_of(file=GrubBootResult().initrds_dir() / initrd)
    qemu.shutdown()
    if not dry_run:
        assert qemu.start() == BootStatuses.GrubFailedToLoadKernelOrInitrd

def qemu_grub_run_tests(dry_run: bool, vm_dir: pl.Path) -> None:
    with QemuTestingEnv(dry_run, vm_dir) as image_and_uefi:
        qemu_grub_test_tamper_with_shim(dry_run, image_and_uefi[0], image_and_uefi[1])
    logger.info(f'qemu_grub_test_tamper_with_shim successfully passed')

    with QemuTestingEnv(dry_run, vm_dir) as image_and_uefi:
        qemu_grub_test_tamper_with_grub(dry_run, image_and_uefi[0], image_and_uefi[1])
    logger.info(f'qemu_grub_test_tamper_with_grub successfully passed')

    with QemuTestingEnv(dry_run, vm_dir) as image_and_uefi:
        qemu_grub_test_tamper_with_grub_cfg(dry_run, image_and_uefi[0], image_and_uefi[1])
    logger.info(f'qemu_grub_test_tamper_with_grub_cfg successfully passed')

    with QemuTestingEnv(dry_run, vm_dir) as image_and_uefi:
        qemu_grub_test_tamper_with_grub_cfg_sig(dry_run, image_and_uefi[0], image_and_uefi[1])
    logger.info(f'qemu_grub_test_tamper_with_grub_cfg_sig successfully passed')

    with QemuTestingEnv(dry_run, vm_dir) as image_and_uefi:
        qemu_grub_test_tamper_with_kernel(dry_run, image_and_uefi[0], image_and_uefi[1])
    logger.info(f'qemu_grub_test_tamper_with_kernel successfully passed')

    with QemuTestingEnv(dry_run, vm_dir) as image_and_uefi:
        qemu_grub_test_tamper_with_initrd(dry_run, image_and_uefi[0], image_and_uefi[1])
    logger.info(f'qemu_grub_test_tamper_with_initrd successfully passed')
































# ==============================================================================================================
# ==============================================================================================================
# Main

class TestMain(ut.TestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.this_file = pl.Path(__file__).expanduser().resolve()

    def normalise(self, cmd: str, dry_run: bool = False) -> str:
        if dry_run:
            return cmd.replace("./secboot.py ", f'{self.this_file} --no-run-tests --dry-run ')
        else:
            return cmd.replace("./secboot.py ", f'{self.this_file} --no-run-tests ')
    def test_BACKUP_CERTS_FROM_UEFI_EXAMPLE(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            os.chdir(pl.Path(str_work_dir))
            res: ExecRes = exec(False, self.normalise(BACKUP_CERTS_FROM_UEFI_EXAMPLE))
            self.assertTrue(res.is_ok(), f'{self.normalise(BACKUP_CERTS_FROM_UEFI_EXAMPLE)}')
            self.assertTrue(pl.Path(f'sec_out/{UefiVars.PK.name}.old.esl').exists())
            self.assertTrue(pl.Path(f'sec_out/{UefiVars.KEK.name}.old.esl').exists())
            self.assertTrue(pl.Path(f'sec_out/{UefiVars.db.name}.old.esl').exists())
            self.assertTrue(pl.Path(f'sec_out/{UefiVars.dbx.name}.old.esl').exists())

    def test_GENERATE_GPG_KEYS_EXAMPLE_and_RE_SIGN_FILE_WITH_GPG_EXAMPLE_FS_non_empty_passphrase(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            passphrase: str = "test"
            gen_gpg_cmd: str = GENERATE_GPG_KEYS_EXAMPLE.replace('--gpg/pass ""', f'--gpg/pass "{passphrase}"')
            gen_res: ExecRes = exec(False, self.normalise(gen_gpg_cmd))
            self.assertTrue(gen_res.is_ok())
            with open(work_dir / 'sec_out/shimx64.efi', 'w') as f:
                f.write("let's pretend this is shim")

            GNUPGHOME: pl.Path = work_dir / "sec_out/gpg"
            key_id: str = Gpg.get_last_added_primary_key_fingerprint(dry_run=False, gpg_home=GNUPGHOME)
            sign_cmd: str = RE_SIGN_FILE_WITH_GPG_EXAMPLE_FS
            sign_cmd = sign_cmd.replace("--gpg/key-id ADDB2...", f'--gpg/key-id {key_id}')
            sign_cmd = sign_cmd.replace("--GNUPGHOME ~/.gnupg/", f'--GNUPGHOME {GNUPGHOME}')
            sign_cmd += f' --gpg/pass "{passphrase}"'
            sign_res: ExecRes = exec(False, self.normalise(sign_cmd))
            self.assertTrue(sign_res.is_ok(), sign_res)
    def test_GENERATE_UEFI_KEYS_EXAMPLE_and_RE_SIGN_EFI_FILE_EXAMPLE_FS(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            os.chdir(pl.Path(str_work_dir))
            gen_res: ExecRes = exec(False, self.normalise(GENERATE_UEFI_KEYS_EXAMPLE))
            self.assertTrue(gen_res.is_ok())
            for var in UefiVars:
                if var == UefiVars.dbx:
                    continue
                for ext in ['key', 'cer', 'crt']:
                    p = pl.Path(f'sec_out/{var.name}.{ext}')
                    self.assertTrue(p.exists(), p)

            shim_signed: pl.Path = pl.Path('/usr/lib/shim/shimx64.efi.signed')
            grub: pl.Path = pl.Path('/boot/grub/x86_64-efi/grub.efi')
            to_sign: pl.Path = pl.Path()
            if shim_signed.exists():
                to_sign = shim_signed
            elif grub.exists():
                to_sign = grub
            if to_sign == pl.Path():
                return
            safe_copy(dry_run=False, src=to_sign, dst=pl.Path("sec_out/shimx64.efi.signed"))
            sign_res: ExecRes = exec(False, self.normalise(RE_SIGN_EFI_FILE_EXAMPLE_FS))
            self.assertTrue(sign_res.is_ok(), sign_res)
    def test_dry_run_RE_SIGN_EFI_FILE_EXAMPLE_YUBIKEY(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(RE_SIGN_EFI_FILE_EXAMPLE_YUBIKEY, dry_run=True))
            self.assertTrue(res.is_ok())
    def test_dry_run_RE_SIGN_FILE_WITH_GPG_EXAMPLE_YUBIKEY(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(RE_SIGN_FILE_WITH_GPG_EXAMPLE_YUBIKEY, dry_run=True))
            self.assertTrue(res.is_ok())


    def test_dry_run_ENROLL_SSL_TO_YUBIKEY_EXAMPLE(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(ENROLL_SSL_TO_YUBIKEY_EXAMPLE, dry_run=True))
            self.assertTrue(res.is_ok())


    def test_dry_run_MAKE_NEW_GRUB_BOOT_EXAMPLE_FS(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(MAKE_NEW_GRUB_BOOT_EXAMPLE_FS, dry_run=True))
            self.assertTrue(res.is_ok(), res)
    def test_dry_run_MAKE_NEW_GRUB_BOOT_EXAMPLE_YUBIKEY(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(MAKE_NEW_GRUB_BOOT_EXAMPLE_YUBIKEY, dry_run=True))
            self.assertTrue(res.is_ok(), res)
    def test_dry_run_MAKE_NEW_EFISTUB_BOOT_EXAMPLE_FS(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(MAKE_NEW_EFISTUB_BOOT_EXAMPLE_FS, dry_run=True))
            self.assertTrue(res.is_ok(), res)
    def test_dry_run_MAKE_NEW_EFISTUB_BOOT_EXAMPLE_YUBIKEY(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(MAKE_NEW_EFISTUB_BOOT_EXAMPLE_YUBIKEY, dry_run=True))
            self.assertTrue(res.is_ok(), res)


    def test_dry_run_QEMU_INITIALISE_EFISTUB_EXAMPLE(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(QEMU_INITIALISE_EFISTUB_EXAMPLE, dry_run=True))
            self.assertTrue(res.is_ok(), res)
    def test_dry_run_QEMU_RUN_EFISTUB_TESTS_EXAMPLE(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(QEMU_RUN_EFISTUB_TESTS_EXAMPLE, dry_run=True))
            self.assertTrue(res.is_ok(), res)
    def test_dry_run_QEMU_INITIALISE_GRUB_EXAMPLE(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(QEMU_INITIALISE_GRUB_EXAMPLE, dry_run=True))
            self.assertTrue(res.is_ok(), res)
    def test_dry_run_QEMU_RUN_GRUB_TESTS_EXAMPLE(self):
        with tempf.TemporaryDirectory(prefix="secboot_testing_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            os.chdir(work_dir)
            (work_dir / "sec_out").mkdir(parents=True, exist_ok=True)
            res: ExecRes = exec(False, self.normalise(QEMU_RUN_GRUB_TESTS_EXAMPLE, dry_run=True))
            self.assertTrue(res.is_ok(), res)



class NfcReaderArg:
    @staticmethod
    def add_arg(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--uefi/nfc-reader', type=str,
                            help=f'(Only if "yu" engine is used and only if it is used over NFC interface.) An id'
                                 f'(or a prefix thereof) of NFC reader. It is needed for Yubikey soft to be able to '
                                 f'correctly talk to Yubikey. You can obtain one by running: '
                                 f'"yubico-piv-tool -a status -v2", see more info here '
                                 f'https://github.com/Yubico/yubico-piv-tool/issues/298')

    @staticmethod
    def handle_arg(args) -> None:
        d: t.Dict[str, str] = vars(args)
        nfc_reader: str = d["uefi/nfc_reader"]
        if nfc_reader:
            global NFC_READER_HINT
            NFC_READER_HINT = f"-r '{nfc_reader}'"


@dc.dataclass
class UserCreds:
    piv_pass: t.Union[None, str] = None
    gpg_pass: t.Union[None, str] = None

    def __init__(self, piv_pass: t.Union[None, str], gpg_pass: t.Union[None, str]):
        self.gpg_pass = gpg_pass
        self.piv_pass = piv_pass
        if self.piv_pass is not None:
            self.piv_pass = self.piv_pass[:8] # Yubikey support at most 8 characters long passwords

    @staticmethod
    def ask(dry_run: bool, ask_piv: bool = False, ask_gpg: bool = False) -> 'UserCreds':
        if dry_run:
            return UserCreds("asdf", "asdf")
        if not any([ask_piv, ask_gpg]):
            return UserCreds(None, None)
        from getpass import getpass
        if all([ask_piv, ask_gpg]):
            print(f'Enter passwords, you have two options:')
            print(f'  - <PIV password><TAB><GPG password> if they are different')
            print(f'  - <password> if they are the same')
            string: str = getpass(prompt='')
            list: t.List[str] = string.split('\t')
            assert len(list) == 1 or len(list) == 2
            if len(list) == 1:
                return UserCreds(piv_pass=list[0], gpg_pass=list[0])
            return UserCreds(piv_pass=list[0], gpg_pass=list[1])
        if ask_piv:
            return UserCreds(piv_pass=getpass(prompt='Enter your PIV password:'), gpg_pass=None)
        return UserCreds(piv_pass=None, gpg_pass=getpass(prompt='Enter your GPG password:'))




ENGINES: t.List[str] = ['fs', 'yu']
class UefiEnginesArgsFactory:
    @staticmethod
    def add_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--uefi/engine', type=str, required=True, choices=ENGINES,
                            help=f'Defines source of key info: "fs" - a directory on filesystem, "yu" - Yubikey')
        key_names: t.List[str] = [k.name for k, v in YubikeyUefi._YUBIKEY_SLOT_MAPPING.items()]
        key_names.remove(UefiVars.PK.name) # Cannot sign with PK
        parser.add_argument('--uefi/key', type=str, default=UefiVars.db.name, choices=key_names,
                            help=f'which key/cert to use')
        parser.add_argument('--uefi/keys-dir', type=str,
                            help=f'(Only if "fs" engine is used) Path to a directory with keys/certs')
        parser.add_argument('--uefi/pass', type=str, help='If set, will be used as passphrase for SSL keys password')
        NfcReaderArg.add_arg(parser)

    @staticmethod
    def ask_for_pass(args) -> bool:
        if vars(args)["uefi/pass"] is not None:
            return False # Explicitly specified, no need to ask
        # Since we do not generate fs keys with password, the only thing to check is used engine:
        return vars(args)["uefi/engine"] == 'yu'

    @staticmethod
    def create_from_args(args, work_dir: pl.Path, asked_password: t.Union[None, str]) -> UefiEngine:
        d: t.Dict[str, str] = vars(args)

        var: t.Union[UefiVars, None] = UefiVars[d["uefi/key"]] if "uefi/key" in d else None
        engine: str = d["uefi/engine"]
        if engine == 'fs':
            return FsUefi(dry_run=args.dry_run, keys_dir=pl.Path(d["uefi/keys_dir"]).expanduser().resolve(), var=var)
        elif engine == 'yu':
            if d["uefi/pass"] is not None:
                password = d["uefi/pass"]
            else:
                password = asked_password
            # In case of yubikey the password has to be either specified via --uefi/pass, or
            # asked by us.
            assert password is not None
            NfcReaderArg.handle_arg(args)
            return YubikeyUefi(dry_run=args.dry_run, work_dir=work_dir, var=var, password=password)
        else:
            assert False


class GpgEnginesArgsFactory:
    @staticmethod
    def add_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--gpg/engine', type=str, required=True, choices=ENGINES,
                            help=f'Defines source of key info: "fs" - a directory on filesystem, "yu" - Yubikey')
        parser.add_argument('--gpg/pub-key', type=str, help=f'(Only if "yu" engine is used) Path to a public GPG key')
        parser.add_argument('--gpg/key-id', type=str,
                            help=f'(Only if "fs" engine is used) GPG key id to use. Use "gpg --list-keys" to get it.')
        parser.add_argument('--GNUPGHOME', type=str,
                            help=f'(Only if "fs" engine is used) Path to GPG home directory (usually "~/.gnupg").')
        parser.add_argument('--use-gpg-agent-for-pass', action='store_true',
                            help='If set, standard gpg-agent will be used. Disadvantage of this is that you might '
                                 'need to to enter your password several times. If not set, the script will ask '
                                 'you your GPG password and use --passphrase option of GPG')
        parser.add_argument('--gpg/pass', type=str, help='If set, will be used as passphrase for GPG. '
                                                         'Takes preceedence over --use-gpg-agent-for-pass')

    @staticmethod
    def ask_for_pass(args) -> bool:
        if vars(args)["gpg/pass"] is not None:
            return False # Explicitly specified, no need to ask
        if bool(args.use_gpg_agent_for_pass):
            return False # User wants gpg ask them their password, not us
        return True

    @staticmethod
    def create_from_args(args, work_dir: pl.Path, asked_password: t.Union[None, str]) -> WrappedGpg:
        d: t.Dict[str, str] = vars(args)
        if d["gpg/pass"] is not None:
            password = d["gpg/pass"]
        else:
            password = asked_password

        engine: str = d["gpg/engine"]
        if engine == 'fs':
            GNUPGHOME: str = d["GNUPGHOME"]
            if not GNUPGHOME:
                logger.critical("--GNUPGHOME is missing!")
            return WrappedFsGpg(dry_run=args.dry_run,
                                password=password,
                                GNUPGHOME=pl.Path(GNUPGHOME).expanduser().resolve(),
                                key_id=d["gpg/key_id"])
        elif engine == 'yu':
            return WrappedYubikeyGpg(dry_run=args.dry_run,
                                     password=password,
                                     work_dir=work_dir,
                                     pub_key=pl.Path(d["gpg/pub_key"]).expanduser().resolve())
        else:
            assert False


def main():
    parser = argparse.ArgumentParser(description=f'This is a script for managing Secure boot. Many operations require '
                                                 f'root. Commands below with prefix "ot/" (stands for "one-time") '
                                                 f'are supposed to be run once, during initial setup.')
    parser.add_argument("--dry-run", action='store_true')
    parser.add_argument("--log-level", type=str, choices=['DEBUG', 'INFO', 'ERROR', 'DISABLED'],
                        default='INFO', help='Log level')
    subparsers = parser.add_subparsers(dest='subparser_name')

    # Replace in Python 3.9 with:
    # parser.add_argument('--run-tests', default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument('--run-tests', dest='run_tests', action='store_true')
    parser.add_argument('--no-run-tests', dest='run_tests', action='store_false')
    parser.set_defaults(run_tests=os.uname()[1] == "Impedance")

    # -----------------------------------------------------------------------------------------------
    parser_backup_cert_from_uefi = subparsers.add_parser(
        BACKUP_CERTS_FROM_UEFI_CMD_LINE_OPT,
        help=f'Exports PK/KEK/db/dbx/MOK from UEFI as files. You need to store them on an external USB flash drive, '
             f'just in case. Example of usage: "{BACKUP_CERTS_FROM_UEFI_EXAMPLE}"')
    parser_backup_cert_from_uefi.add_argument('-o', type=str, required=True, help='Output directory')

    # -----------------------------------------------------------------------------------------------
    parser_generate_gpg_keys = subparsers.add_parser(
        GENERATE_GPG_KEYS_CMD_LINE_OPT,
        help=f'Generates new GPG keys. You might want to create a temporary memory-backed fs for the task: "sudo mount -t tmpfs -o size=10G,uid=(id -u) tmpfs sec_out" and use the directory as temporary GPG HOME. Example of usage: "{GENERATE_GPG_KEYS_EXAMPLE}"')
    parser_generate_gpg_keys.add_argument('--GNUPGHOME', type=str, required=True,
                                          help=f'Path to GPG home directory (usually "~/.gnupg").')
    parser_generate_gpg_keys.add_argument('--id', type=str, required=True,
                                          help=f'Your human readable ID. Will be stored in GPG keys.')
    parser_generate_gpg_keys.add_argument('--gpg/pass', type=str, help=f'GPG passphrase')



    # -----------------------------------------------------------------------------------------------
    parser_generate_uefi_keys = subparsers.add_parser(
        GENERATE_UEFI_KEYS_CMD_LINE_OPT,
        help=f'Generates new (your own!) UEFI (PK/KEK/db) keys and certificates on filesystem. You might want to '
             f'create a temporary memory-backed fs for the task: "sudo mount -t tmpfs -o size=10G,uid=(id -u) '
             f'tmpfs sec_out" and move them then to a Yubikey, see {ENROLL_SSL_TO_YUBIKEY_CMD_LINE_OPT}. '
             f'Example of usage: "{GENERATE_UEFI_KEYS_EXAMPLE}"')
    parser_generate_uefi_keys.add_argument('-o', type=str, required=True, help='Output directory')
    parser_generate_uefi_keys.add_argument('--id', type=str, default="",
                                             help=f'Your human readable ID. Will be stored in certificates. '
                                                  f'Can be empty.')

    # -----------------------------------------------------------------------------------------------
    parser_enroll_ssl_to_yubikey = subparsers.add_parser(
        ENROLL_SSL_TO_YUBIKEY_CMD_LINE_OPT,
        help=f'Enrolls PK/KEK/DB keys and certificates to Yubikey. Example of usage: "{ENROLL_SSL_TO_YUBIKEY_EXAMPLE}"')
    parser_enroll_ssl_to_yubikey.add_argument('--keys-dir', type=str, required=True,
                                              help=f'Directory where PK/KEK/DB keys and certificates can be found')
    NfcReaderArg.add_arg(parser_enroll_ssl_to_yubikey)


    # -----------------------------------------------------------------------------------------------
    parser_enroll_ssl_to_uefi = subparsers.add_parser(
        ENROLL_SSL_TO_UEFI_CMD_LINE_OPT,
        help=f'Enrolls PK/KEK/DB certificates to UEFI. Assumes that UEFI is in "Setup Mode" (temporarily disable '
             f'secure boot, and delete all preexisting certificates). Example of usage: '
             f'"{ENROLL_SSL_TO_UEFI_EXAMPLE_FS}" or "{ENROLL_SSL_TO_UEFI_EXAMPLE_YUBIKEY}"')
    UefiEnginesArgsFactory.add_args(parser_enroll_ssl_to_uefi)


    # -----------------------------------------------------------------------------------------------
    parser_re_sign_efi = subparsers.add_parser(
        RE_SIGN_EFI_FILE_CMD_LINE_OPT,
        help=f'[The command is not supposed to be used on its own. You can skip it.] Removes all existing signatures '
             f'from a given EFI executable file and signs it with a provided (your own!) certificate. Example of '
             f'usage: "{RE_SIGN_EFI_FILE_EXAMPLE_FS}" or "{RE_SIGN_EFI_FILE_EXAMPLE_YUBIKEY}"')
    parser_re_sign_efi.add_argument('--file-to-sign', type=str, required=True,
                                    help='Path to file to sign. Backup will be created.')
    parser_re_sign_efi.add_argument('--signed-file-path', type=str, required=False,
                                    help='Path to the resulting (signed) file. If empty, will be defaulted '
                                         'to the value of --file-to-sign.')
    UefiEnginesArgsFactory.add_args(parser_re_sign_efi)


    # -----------------------------------------------------------------------------------------------
    parser_re_sign_with_gpg = subparsers.add_parser(
        RE_SIGN_FILE_WITH_GPG_CMD_LINE_OPT,
        help=f'[The command is not supposed to be used on its own. You can skip it.] Produces a detached GPG '
             f'signature using GPG. The command can be useful if you wish to make manual changes to grub.cfg '
             f'and then re-sign it. Example of usage: "{RE_SIGN_FILE_WITH_GPG_EXAMPLE_FS}" or '
             f'"{RE_SIGN_FILE_WITH_GPG_EXAMPLE_YUBIKEY}"')
    parser_re_sign_with_gpg.add_argument('--file-to-sign', type=str, required=True,
                                    help='Path to file to sign.')
    parser_re_sign_with_gpg.add_argument('--signature-path', type=str, required=False,
                                    help='Path to the resulting signature. If empty, will be defaulted '
                                         'to the value of --file-to-sign + .sig.')
    GpgEnginesArgsFactory.add_args(parser_re_sign_with_gpg)

    # -----------------------------------------------------------------------------------------------

    pbkdf_grub_pass_path_help: str = \
        'Path to a file that contains PBKDF2 GRUB password. Example of how you can generate one: ' \
        '"grub-mkpasswd-pbkdf2 -c 50000000". "-c 50000000" means that when an adversary will brute-force your ' \
        'password on a cluster of machines, it will take just ~2 minutes for one try, so, feel free to _increase_ ' \
        'the iteration count (until you feel comfortable with the time required). Add the hash in a file: ' \
        '"echo grub.pbkdf2.sha512.10000.XXX > ~/grub_pbkdf2_pass", and specify the path to the file as an ' \
        'argument of the option'

    parser_prepare_new_grub_boot = subparsers.add_parser(
        MAKE_NEW_GRUB_BOOT_CMD_LINE_OPT,
        help=f'Prepares new content of /boot/efi. For testing, you might want to specify "--boot-dir ./testing-boot". '
             f'Example of usage: "sudo {MAKE_NEW_GRUB_BOOT_EXAMPLE_FS}" or "sudo {MAKE_NEW_GRUB_BOOT_EXAMPLE_YUBIKEY}"')
    parser_prepare_new_grub_boot.add_argument('--boot-dir', type=str, default='/boot', help='Boot dir.')
    parser_prepare_new_grub_boot.add_argument('--work-dir', type=str, help='Work dir.')
    parser_prepare_new_grub_boot.add_argument('--backups-dir', type=str, default='/bb/',
                                                     help='Directory where to backup existing boot')
    parser_prepare_new_grub_boot.add_argument('--pbkdf-grub-pass-path', type=str, required=True,
                                                     help=pbkdf_grub_pass_path_help)
    UefiEnginesArgsFactory.add_args(parser_prepare_new_grub_boot)
    GpgEnginesArgsFactory.add_args(parser_prepare_new_grub_boot)

    # -----------------------------------------------------------------------------------------------

    parser_prepare_new_efistub_boot = subparsers.add_parser(
        MAKE_NEW_EFISTUB_BOOT_CMD_LINE_OPT,
        help=f'Prepares new content of /boot/efi. For testing, you might want to specify "--boot-dir ./testing-boot". '
             f'Example of usage: "sudo {MAKE_NEW_EFISTUB_BOOT_EXAMPLE_FS}" or '
             f'"sudo {MAKE_NEW_EFISTUB_BOOT_EXAMPLE_YUBIKEY}"')
    parser_prepare_new_efistub_boot.add_argument('--work-dir', type=str, help='Work dir.')
    parser_prepare_new_efistub_boot.add_argument('--backups-dir', type=str, default='/bb/',
                                                 help='Directory where to backup existing boot')
    parser_prepare_new_efistub_boot.add_argument('--boot-dir', type=str, default='/boot', help='Boot dir.')
    parser_prepare_new_efistub_boot.add_argument('--disk', type=str, required=True,
                                                 help='Disk (without partition number). You can check it in the '
                                                      'output of "mount | grep efi". For example: /dev/nvme0n1')
    parser_prepare_new_efistub_boot.add_argument('--partition', type=int, required=True,
                                                 help='Partition number. You can check it in the output of'
                                                      '"mount | grep efi". For example: 1')
    parser_prepare_new_efistub_boot.add_argument('--kernel-parameters', type=str, required=False,
                                                 help='Kernel args / parameters')

    UefiEnginesArgsFactory.add_args(parser_prepare_new_efistub_boot)


    # -----------------------------------------------------------------------------------------------

    qemu_efistub_initialise_parser = subparsers.add_parser(
        QEMU_INITIALISE_EFISTUB_CMD_LINE_OPT,
        help=f'Guides you through the process of (1) creation of a new VM in QEMU and (2) making it interactable '
             f'from host console. After this is done, it uses the VM for testing itself: it (a) copies itself in the '
             f'VM, (b) generates SSL/UEFI keys using {GENERATE_UEFI_KEYS_CMD_LINE_OPT}, (c) creates new boot via '
             f'{MAKE_NEW_EFISTUB_BOOT_CMD_LINE_OPT} and finally (d) ensures the VM can successfully reboot. '
             f'See also {QEMU_RUN_EFISTUB_TESTS_CMD_LINE_OPT}. Example of usage: {QEMU_INITIALISE_EFISTUB_EXAMPLE}')
    qemu_efistub_initialise_parser.add_argument('--vm-dir', type=str, required=True,
                                        help=f'Directory where VM images will be stored')

    # -----------------------------------------------------------------------------------------------

    qemu_run_efistub_tests_parser = subparsers.add_parser(
        QEMU_RUN_EFISTUB_TESTS_CMD_LINE_OPT,
        help=f'Runs "integration" tests in QEMU VM. The tests verify that (1) the OS loads after all '
             f'modifications, (2) the OS does NOT load if anything (unified kernel image) was changed. Example '
             f'of usage: "{QEMU_RUN_EFISTUB_TESTS_EXAMPLE}"')
    qemu_run_efistub_tests_parser.add_argument('--vm-dir', type=str, required=True,
                                            help=f'Path to a directory where you performed '
                                                 f'{QEMU_INITIALISE_EFISTUB_CMD_LINE_OPT}. '
                                                 f'Example of usage: "{QEMU_RUN_EFISTUB_TESTS_EXAMPLE}"')


    # -----------------------------------------------------------------------------------------------

    qemu_grub_initialise_parser = subparsers.add_parser(
        QEMU_INITIALISE_GRUB_CMD_LINE_OPT,
        help=f'Guides you through the process of (1) creation of a new VM in QEMU and (2) making it interactable '
             f'from host console. After this is done, it uses the VM for testing itself: it (a) copies itself in the '
             f'VM, (b) generates GPG keys in the VM using {GENERATE_GPG_KEYS_CMD_LINE_OPT}, (c) generates SSL/UEFI '
             f'keys using {GENERATE_UEFI_KEYS_CMD_LINE_OPT}, (d) creates new boot via {MAKE_NEW_GRUB_BOOT_CMD_LINE_OPT} '
             f'and finally (d) ensures the VM can successfully reboot. See also {QEMU_RUN_GRUB_TESTS_CMD_LINE_OPT}. '
             f'Example of usage: {QEMU_INITIALISE_GRUB_EXAMPLE}')
    qemu_grub_initialise_parser.add_argument('--vm-dir', type=str, required=True,
                                       help=f'Directory where VM images will be stored')

    # -----------------------------------------------------------------------------------------------

    qemu_run_grub_tests_parser = subparsers.add_parser(
        QEMU_RUN_GRUB_TESTS_CMD_LINE_OPT,
        help=f'Runs "integration" tests in QEMU VM. The tests verify that (1) the OS loads after all '
             f'modifications, (2) the OS does NOT load if anything (kernel, initrd, GRUB, GRUB config, shim) was '
             f'changed. Example of usage: "{QEMU_RUN_GRUB_TESTS_EXAMPLE}"')
    qemu_run_grub_tests_parser.add_argument('--vm-dir', type=str, required=True,
                                       help=f'Path to a directory where you performed {QEMU_INITIALISE_GRUB_CMD_LINE_OPT}. '
                                            f'Example of usage: "{QEMU_RUN_GRUB_TESTS_EXAMPLE}"')


    # -----------------------------------------------------------------------------------------------

    args = parser.parse_args()
    log_levels = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'ERROR': logging.ERROR, 'DISABLED': logging.CRITICAL + 1}
    logger.setLevel(level=log_levels[args.log_level])

    def python_import_exists(import_name: str) -> bool:
        from importlib import util
        return util.find_spec(import_name) is not None
    if not python_import_exists("pexpect"):
        logger.critical("Python module pexpect is not installed, Install it manually: "
                        "sudo apt install python3-pexpect. Exiting...")

    if args.run_tests:
        print('Running quick self-test (you can disable them with --no-run-tests)...\n')
        cwd_backup = os.getcwd()
        ut.main(argv=['first-arg-is-ignored'], exit=False)
        os.chdir(cwd_backup)
        print(f'Testing Done\n')


    if args.subparser_name == BACKUP_CERTS_FROM_UEFI_CMD_LINE_OPT:
        backup_certs_from_uefi(dry_run=args.dry_run, output_dir=pl.Path(args.o).expanduser().resolve())
        print(f'\nNext steps:\nUse {GENERATE_UEFI_KEYS_CMD_LINE_OPT} and '
              f'{GENERATE_GPG_KEYS_CMD_LINE_OPT} to generate keys and certificates.')
    elif args.subparser_name == GENERATE_UEFI_KEYS_CMD_LINE_OPT:
        FsUefi.generate_keys(dry_run=args.dry_run, keys_dir=pl.Path(args.o).expanduser().resolve(), id=args.id)
        print(f'\nNext steps:\nEnroll generated certificates in UEFI (either directly by copying DER (.cer) and hashes '
              f'(in the HSH format) on a USB flash drive or by using {ENROLL_SSL_TO_UEFI_CMD_LINE_OPT}).\n'
              f'Enroll them on a Yubikey via {ENROLL_SSL_TO_YUBIKEY_CMD_LINE_OPT}')
    elif args.subparser_name == GENERATE_GPG_KEYS_CMD_LINE_OPT:
        Gpg.generate_keys(dry_run=args.dry_run,
                          gpg_home=pl.Path(args.GNUPGHOME).expanduser().resolve(),
                          id=args.id,
                          passphrase=vars(args)["gpg/pass"] or "")
    elif args.subparser_name == ENROLL_SSL_TO_UEFI_CMD_LINE_OPT:
        with tempf.TemporaryDirectory(prefix="secboot_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            uefi=UefiEnginesArgsFactory.create_from_args(args, work_dir, password='')
            uefi.enroll_certs_to_uefi()
    elif args.subparser_name == ENROLL_SSL_TO_YUBIKEY_CMD_LINE_OPT:
        NfcReaderArg.handle_arg(args)
        YubikeyUefi.enroll_to_yubikey(dry_run=args.dry_run, dir=pl.Path(args.keys_dir).expanduser().resolve())
        print(f'\n')
        print(f'All keys and certificates have been enrolled to Yubikey.')
        print(f'You can now safely remove all of them from filesystem - everything '
              f'required for signing is stored on you Yubikey')
    elif args.subparser_name == RE_SIGN_EFI_FILE_CMD_LINE_OPT:
        file_to_sign: pl.Path = pl.Path(args.file_to_sign).expanduser().resolve()
        signed_file_path: pl.Path = pl.Path(args.signed_file_path).expanduser().resolve() if args.signed_file_path else file_to_sign
        creds: UserCreds = UserCreds.ask(dry_run=args.dry_run, ask_piv=UefiEnginesArgsFactory.ask_for_pass(args))
        with tempf.TemporaryDirectory(prefix="secboot_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            re_sign_efi_file(dry_run=args.dry_run,
                             file_to_sign=file_to_sign,
                             signed_file_path=signed_file_path,
                             uefi=UefiEnginesArgsFactory.create_from_args(args, work_dir, creds.piv_pass))
    elif args.subparser_name == RE_SIGN_FILE_WITH_GPG_CMD_LINE_OPT:
        file_and_sig: FileAndSig = FileAndSig(pl.Path(args.file_to_sign).expanduser().resolve())
        if args.signature_path:
            file_and_sig.sig = pl.Path(args.signature_path).expanduser().resolve()
        creds: UserCreds = UserCreds.ask(dry_run=args.dry_run, ask_gpg=GpgEnginesArgsFactory.ask_for_pass(args))
        with tempf.TemporaryDirectory(prefix="secboot_") as str_work_dir:
            work_dir: pl.Path = pl.Path(str_work_dir)
            with GpgEnginesArgsFactory.create_from_args(args, work_dir, creds.gpg_pass) as gpg:
                re_sign_file_with_gpg(dry_run=args.dry_run, file_and_sig=file_and_sig, gpg=gpg)
    elif args.subparser_name == MAKE_NEW_GRUB_BOOT_CMD_LINE_OPT:
        def continue_makeing_new_boot(args, work_dir: pl.Path) -> None:
            creds: UserCreds = UserCreds.ask(dry_run=args.dry_run,
                                             ask_piv=UefiEnginesArgsFactory.ask_for_pass(args),
                                             ask_gpg=GpgEnginesArgsFactory.ask_for_pass(args))
            make_new_grub_boot(dry_run=args.dry_run,
                               work_dir=work_dir,
                               backups_dir=pl.Path(args.backups_dir).expanduser().resolve(),
                               boot_dir=pl.Path(args.boot_dir).expanduser().resolve(),
                               wrapped_gpg=GpgEnginesArgsFactory.create_from_args(args, work_dir, creds.gpg_pass),
                               uefi=UefiEnginesArgsFactory.create_from_args(args, work_dir, creds.piv_pass),
                               pbkdf_grub_pass_path=pl.Path(args.pbkdf_grub_pass_path).expanduser().resolve())
        if args.work_dir:
            work_dir: pl.Path = pl.Path(args.work_dir).expanduser().resolve()
            continue_makeing_new_boot(args, work_dir)
        else:
            with tempf.TemporaryDirectory(prefix="secboot_") as str_work_dir:
                work_dir: pl.Path = pl.Path(str_work_dir)
                continue_makeing_new_boot(args, work_dir)

    elif args.subparser_name == MAKE_NEW_EFISTUB_BOOT_CMD_LINE_OPT:
        def continue_makeing_new_boot(args, work_dir: pl.Path) -> None:
            creds: UserCreds = UserCreds.ask(dry_run=args.dry_run,
                                             ask_piv=UefiEnginesArgsFactory.ask_for_pass(args),
                                             ask_gpg=False)
            make_new_efistub_boot(dry_run=args.dry_run,
                                  work_dir=work_dir,
                                  backups_dir=pl.Path(args.backups_dir).expanduser().resolve(),
                                  boot_dir=pl.Path(args.boot_dir).expanduser().resolve(),
                                  disk=args.disk,
                                  partition=args.partition,
                                  kernel_parameters=args.kernel_parameters,
                                  uefi=UefiEnginesArgsFactory.create_from_args(args, work_dir, creds.piv_pass))
        if args.work_dir:
            work_dir: pl.Path = pl.Path(args.work_dir).expanduser().resolve()
            continue_makeing_new_boot(args, work_dir)
        else:
            with tempf.TemporaryDirectory(prefix="secboot_") as str_work_dir:
                work_dir: pl.Path = pl.Path(str_work_dir)
                continue_makeing_new_boot(args, work_dir)

    elif args.subparser_name == QEMU_INITIALISE_EFISTUB_CMD_LINE_OPT:
        qemu_efistub_initialise(dry_run=args.dry_run, vm_dir=pl.Path(args.vm_dir).expanduser().resolve())
    elif args.subparser_name == QEMU_RUN_EFISTUB_TESTS_CMD_LINE_OPT:
        qemu_efistub_run_tests(dry_run=args.dry_run, vm_dir=pl.Path(args.vm_dir).expanduser().resolve())
    elif args.subparser_name == QEMU_INITIALISE_GRUB_CMD_LINE_OPT:
        qemu_grub_initialise(dry_run=args.dry_run, vm_dir=pl.Path(args.vm_dir).expanduser().resolve())
    elif args.subparser_name == QEMU_RUN_GRUB_TESTS_CMD_LINE_OPT:
        qemu_grub_run_tests(dry_run=args.dry_run, vm_dir=pl.Path(args.vm_dir).expanduser().resolve())
    else:
        print("No actions requested, exiting...\n")
        parser.print_help()




if __name__ == '__main__':
    main()
