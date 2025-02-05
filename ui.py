import io
import struct
import subprocess
import sys
import os
import shutil
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QFileDialog, QVBoxLayout, \
    QWidget, QMessageBox, QCheckBox, QDesktopWidget


class SignSacker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Software attribute replicator(软件属性复制器) By yuanmeng")
        self.setWindowIcon(QIcon('favicon.ico'))  
        self.resize(700, 400)

        
        screen = QDesktopWidget().screenGeometry()
        window_size = self.geometry()
        x = int((screen.width() - window_size.width()) / 2)
        y = int((screen.height() - window_size.height()) / 2)
        self.move(x, y)

        widget = QWidget(self)
        layout = QVBoxLayout()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        self.file1_label = QLabel("受害者:", self)
        layout.addWidget(self.file1_label)

        self.file1_entry = QLineEdit(self)
        layout.addWidget(self.file1_entry)

        self.choose_button1 = QPushButton("选择需要复制属性的文件", self)
        layout.addWidget(self.choose_button1)
        self.choose_button1.clicked.connect(self.choose_file1)

        self.file2_label = QLabel("掠夺者:", self)
        layout.addWidget(self.file2_label)

        self.file2_entry = QLineEdit(self)
        layout.addWidget(self.file2_entry)

        self.choose_button2 = QPushButton("选择需要伪造属性的文件", self)
        layout.addWidget(self.choose_button2)
        self.choose_button2.clicked.connect(self.choose_file2)

        self.output_label = QLabel("生成文件名:", self)
        layout.addWidget(self.output_label)

        self.output_entry = QLineEdit(self)
        layout.addWidget(self.output_entry)

        self.icon_checkbox = QCheckBox("复制受害者高清图标", self)
        self.details_checkbox = QCheckBox("复制受害者所有详细信息（右键属性->详细信息。包括文件说明，文件版本等）", self)
        layout.addWidget(self.icon_checkbox)
        layout.addWidget(self.details_checkbox)

        self.output_label = QLabel("------------------------------------------------------------------------------------", self)
        layout.addWidget(self.output_label)
        self.output_label = QLabel("温馨提示：", self)
        layout.addWidget(self.output_label)
        self.output_label = QLabel("1.掠夺后图标若无变化请粘贴到新的文件夹刷新即可。", self)
        layout.addWidget(self.output_label)
        self.output_label = QLabel("2.本软件根据已经停更的项目进行优化及调整能复制任意exe，dll文件属性信息。", self)
        layout.addWidget(self.output_label)
        self.output_label = QLabel("3.优化了报错响应信息。", self)
        layout.addWidget(self.output_label)
        self.output_label = QLabel("4.github开源地址:https://github.com/yuanmeng-MINGI/Software_attribute_replicator。", self)
        layout.addWidget(self.output_label)
        self.output_label = QLabel("------------------------------------------------------------------------------------", self)
        layout.addWidget(self.output_label)

        self.process_button = QPushButton("生成文件", self)
        layout.addWidget(self.process_button)
        self.process_button.clicked.connect(self.process_files)

        self.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #333;
            }
            QLineEdit, QPushButton {
                font-size: 14px;
                height: 30px;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 6px 12px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)

    def choose_file1(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件1", "", "Executable Files (*.exe *.dll)")
        if file_name:
            self.file1_entry.setText(file_name)

    def choose_file2(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择文件2", "", "Executable Files (*.exe *.dll)")
        if file_name:
            self.file2_entry.setText(file_name)
            # 自动填充生成文件名的文本框
            base_name = os.path.basename(file_name)
            extension = os.path.splitext(base_name)[1]
            if extension.lower() == ".dll":
                output_file = os.path.splitext(base_name)[0] + "-Signed.dll"
            else:
                output_file = os.path.splitext(base_name)[0] + "-Signed.exe"
            self.output_entry.setText(os.path.join(os.getcwd(), output_file))

    def process_files(self):
        file1_path = self.file1_entry.text()
        file2_path = self.file2_entry.text()
        output_file = self.output_entry.text()
        # 验证文件的有效性
        if not os.path.exists(file1_path) or not os.path.isfile(file1_path):
            self.show_message_box("错误", "文件1无效！")
            return
        if not os.path.exists(file2_path) or not os.path.isfile(file2_path):
            self.show_message_box("错误", "文件2无效！")
            return
        icon = self.icon_checkbox.isChecked()
        version_info = self.details_checkbox.isChecked()
        try:
            if version_info:
                info_sacker(file1_path, file2_path)
            if icon:
                ico_sacker(file1_path, file2_path)
            cert = copyCert(file1_path)
            writeCert(cert, file2_path, output_file)
            message = f"签名已写入：{output_file}"
            self.show_message_box("生成文件", message)
        except Exception as e:
            self.show_message_box("错误", f"处理文件时出现错误：{e}")

    def show_message_box(self, title, message):
        msg_box = QMessageBox()
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec_()


def gather_file_info_win(binary):
    """获取可执行文件的一些信息，包括PE头中的各个字段的数值。"""
    flItms = {}
    with open(binary, 'rb') as binary_file:
        binary_file.seek(int('3C', 16))
        flItms['buffer'] = 0
        flItms['JMPtoCodeAddress'] = 0
        flItms['dis_frm_pehdrs_sectble'] = 248
        flItms['pe_header_location'] = struct.unpack('<i', binary_file.read(4))[0]
        flItms['COFF_Start'] = flItms['pe_header_location'] + 4
        binary_file.seek(flItms['COFF_Start'])
        flItms['MachineType'] = struct.unpack('<H', binary_file.read(2))[0]
        binary_file.seek(flItms['COFF_Start'] + 2, 0)
        flItms['NumberOfSections'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['TimeDateStamp'] = struct.unpack('<I', binary_file.read(4))[0]
        binary_file.seek(flItms['COFF_Start'] + 16, 0)
        flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['Characteristics'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

        binary_file.seek(flItms['OptionalHeader_start'])
        flItms['Magic'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['MajorLinkerVersion'] = struct.unpack("!B", binary_file.read(1))[0]
        flItms['MinorLinkerVersion'] = struct.unpack("!B", binary_file.read(1))[0]
        flItms['SizeOfCode'] = struct.unpack("<I", binary_file.read(4))[0]
        flItms['SizeOfInitializedData'] = struct.unpack("<I", binary_file.read(4))[0]
        flItms['SizeOfUninitializedData'] = struct.unpack("<I", binary_file.read(4))[0]
        flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
        flItms['BaseOfCode'] = struct.unpack('<I', binary_file.read(4))[0]
        if flItms['Magic'] == 0x20B:
            flItms['ImageBase'] = struct.unpack('<Q', binary_file.read(8))[0]
        else:
            flItms['ImageBase'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['SectionAlignment'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['FileAlignment'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['MajorOperatingSystemVersion'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['MinorOperatingSystemVersion'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['MajorImageVersion'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['MinorImageVersion'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['Win32VersionValue'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['SizeOfImageLoc'] = binary_file.tell()
        flItms['SizeOfImage'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['SizeOfHeaders'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['CheckSum'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['Subsystem'] = struct.unpack('<H', binary_file.read(2))[0]
        flItms['DllCharacteristics'] = struct.unpack('<H', binary_file.read(2))[0]
        if flItms['Magic'] == 0x20B:
            flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary_file.read(8))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary_file.read(8))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary_file.read(8))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary_file.read(8))[0]
        else:
            flItms['SizeOfStackReserve'] = struct.unpack('<I', binary_file.read(4))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<I', binary_file.read(4))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary_file.read(4))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['LoaderFlags'] = struct.unpack('<I', binary_file.read(4))[0]  # zero
        flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary_file.read(4))[0]

        flItms['ExportTableRVA'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['ExportTableSize'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['ImportTableLOCInPEOptHdrs'] = binary_file.tell()

        flItms['ImportTableRVA'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['ImportTableSize'] = struct.unpack('<I', binary_file.read(4))[0]
        flItms['ResourceTable'] = struct.unpack('<Q', binary_file.read(8))[0]
        flItms['ExceptionTable'] = struct.unpack('<Q', binary_file.read(8))[0]
        flItms['CertTableLOC'] = binary_file.tell()
        flItms['CertLOC'] = struct.unpack("<I", binary_file.read(4))[0]
        flItms['CertSize'] = struct.unpack("<I", binary_file.read(4))[0]

    return flItms


def copyCert(exe):
    """从可执行文件中提取签名证书"""
    flItms = gather_file_info_win(exe)

    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        return None

    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert


def writeCert(cert, exe, output):
    """写入证书并输出"""
    flItms = gather_file_info_win(exe)

    if not output:
        output = str(exe) + "_signed"

    shutil.copy2(exe, output)

    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(flItms['CertTableLOC'])
            if cert:
                f.write(struct.pack("<I", len(open(exe, 'rb').read())))
                f.write(struct.pack("<I", len(cert)))
                f.seek(0, io.SEEK_END)
                f.write(cert)
            else:
                f.write(struct.pack("<I", len(open(exe, 'rb').read())))
                f.write(struct.pack("<I", 0))


def ico_sacker(victim, sacker):
    """图标掠夺"""
    save_location = f"{victim}_ico"
    os.system(f'ico_sacker.exe /save "{victim}" "{save_location}" -icons')
    ico_path = os.path.join(save_location, os.listdir(save_location)[0])
    os.system(f'info_sacker.exe {sacker} --set-icon "{ico_path}"')


def get_version_string(file_path, string_name):
    """获取文件版本信息"""
    try:
        cmd = f'info_sacker.exe {file_path} --get-version-string "{string_name}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8')
        return result.stdout.strip()
    except Exception as e:
        print(f"获取版本字符串时出错: {e}")
        return None


def set_version_string(file_path, string_name, string_value):
    """设置文件版本信息"""
    try:
        subprocess.check_call(f'info_sacker.exe {file_path} --set-version-string "{string_name}" "{string_value}"',
                              shell=True)
    except Exception as e:
        print(f"设置版本字符串时出错: {e}")


def info_sacker(victim, sacker):
    """掠夺详细信息"""
    version_strings = {
        "FileDescription": "",
        "FileVersion": "",
        "ProductName": "",
        "ProductVersion": "",
        "CompanyName": "",
        "LegalCopyright": "",
        "InternalName": "",
        "OriginalFilename": ""
    }

    # 获取版本信息
    for string_name in version_strings:
        version_strings[string_name] = get_version_string(victim, string_name)

    # 设置版本信息
    for string_name, string_value in version_strings.items():
        if string_value:
            set_version_string(sacker, string_name, string_value)

    file_version = version_strings.get("FileVersion", "")
    if file_version:
        os.system(f'info_sacker.exe {sacker} --set-file-version "{file_version}"')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SignSacker()
    window.show()
    sys.exit(app.exec_())
