import tenseal as ts
import base64
import os
import datetime
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_aes_key(password: str, salt_type: bytes):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_type, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

# Giả định file Patient.txt ban đầu chứa thông tin dạng:
# Họ tên: Nguyễn Văn A
# CCCD: 012345678912
# Ngày sinh: 15/05/1980
# ...
if not os.path.exists("Patient.txt"):
    print("[-] Không tìm thấy file Patient.txt trong thư mục này!")
    exit()

print("="*65)
print("PHASE 0: KHỞI TẠO - MÃ HÓA AES FILE GỐC")
print("="*65)
mat_khau_aes = getpass.getpass(">> [Ẩn] Nhập mật khẩu AES để khóa file Patient.txt: ")

with open("Patient.txt", "rb") as f:
    raw_data = f.read()

aes_cipher = get_aes_key(mat_khau_aes, b'salt_for_patient_file')
with open("Patient_AES.enc", "wb") as f:
    f.write(aes_cipher.encrypt(raw_data))
print("[+] Đã mã hóa file gốc thành 'Patient_AES.enc'.\n")


print("="*65)
print("PHASE 1: TRÍCH XUẤT CCCD & MÃ HÓA FHE THEO ĐỊNH DANH (LOCAL)")
print("="*65)
X_pass_aes = getpass.getpass(">> [Ẩn] Nhập lại mật khẩu AES để mở hồ sơ: ")

try:
    cipher_local = get_aes_key(X_pass_aes, b'salt_for_patient_file')
    with open("Patient_AES.enc", "rb") as f:
        decrypted_text = cipher_local.decrypt(f.read()).decode('utf-8')
    
    lines = decrypted_text.strip().split('\n')
    
    # ---------------------------------------------------------
    # TỰ ĐỘNG TRÍCH XUẤT CCCD ĐỂ LÀM KHÓA ĐỊNH DANH (MỚI)
    # ---------------------------------------------------------
    cccd = ""
    for line in lines:
        if "CCCD" in line or "Căn cước" in line:
            cccd = line.split(':')[1].strip()
            break
            
    if not cccd:
        print("[-] Không tìm thấy thông tin CCCD trong file Patient.txt!")
        exit()
        
    print(f"[+] Đã nhận diện bệnh nhân có CCCD: {cccd}")
    
    # Phân tích các chỉ số cũ
    ngay_sinh_str = lines[2].strip().split(':')[1]
    nam_sinh = int(ngay_sinh_str.split('/')[2])
    tuoi = float(datetime.datetime.now().year - nam_sinh)
    
    gioi_tinh_str = lines[3].strip()
    gioi_tinh = 1.0 if "Nam" in gioi_tinh_str else 0.0
    
    benh_ly_str = lines[5].strip()
    benh_tim = 1.0 if "HeartAttack" in benh_ly_str else 0.0
    
    patient_vector = [tuoi, gioi_tinh, benh_tim]
    
    # Khởi tạo FHE
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.global_scale = 2**40
    context.generate_galois_keys()
    
    # ---------------------------------------------------------
    # ĐẶT TÊN FILE THEO CCCD ĐỂ PHÂN BIỆT CÁC BỆNH NHÂN (MỚI)
    # ---------------------------------------------------------
    encrypted_fhe_data = ts.ckks_vector(context, patient_vector)
    with open(f"cloud_fhe_data_{cccd}.bin", "wb") as f:
        f.write(encrypted_fhe_data.serialize())
    
    mat_khau_fhe = getpass.getpass(">> [Ẩn] Thiết lập mật khẩu bảo vệ Secret Key FHE: ")
    secret_context = context.serialize(save_secret_key=True)
    fhe_aes_cipher = get_aes_key(mat_khau_fhe, b'salt_for_fhe_key')
    
    # Khóa bí mật lưu theo CCCD tại Local
    with open(f"locked_fhe_sk_{cccd}.enc", "wb") as f:
        f.write(fhe_aes_cipher.encrypt(secret_context))
        
    # Public Context gửi lên Cloud cũng kèm CCCD để Cloud biết luồng xử lý
    context.make_context_public() 
    with open(f"cloud_context_{cccd}.bin", "wb") as f:
        f.write(context.serialize())
        
    print(f"[+] Đã đóng gói bộ dữ liệu và khóa cho bệnh nhân {cccd} thành công!\n")

except Exception as e:
    print("[-] SAI MẬT KHẨU AES hoặc file sai định dạng!")
    exit()


print("="*65)
print("PHASE 2: HÀM TÍNH TOÁN TRÊN ĐÁM MÂY (CLOUD COMPUTING)")
print("="*65)
# Giả lập Cloud nhận lệnh xử lý gói dữ liệu của bệnh nhân có CCCD cụ thể
# (Cloud không biết người này là ai, chỉ biết mã hồ sơ là chuỗi số CCCD)
target_cccd = cccd  # Trong thực tế Cloud sẽ nhận tham số ID/CCCD từ request

with open(f"cloud_context_{target_cccd}.bin", "rb") as f:
    cloud_context = ts.context_from(f.read())

with open(f"cloud_fhe_data_{target_cccd}.bin", "rb") as f:
    cloud_data = ts.ckks_vector_from(cloud_context, f.read())

cloud_weights = [0.5, 10.0, 50.0]
cloud_result = cloud_data.dot(cloud_weights)

# Cloud trả về file kết quả đã được đóng nhãn theo CCCD
with open(f"cloud_fhe_result_{target_cccd}.bin", "wb") as f:
    f.write(cloud_result.serialize())
print(f"[+] Cloud đã tính xong cho hồ sơ {target_cccd}, trả về 'cloud_fhe_result_{target_cccd}.bin'.\n")


print("="*65)
print("PHASE 3: QUẢN LÝ BỘ ĐỆM -> XÁC THỰC BẢN SAO -> CẬP NHẬT BẢN GỐC")
print("="*65)

input_cccd = input(">> Nhập số CCCD bệnh nhân cần nhận kết quả từ Cloud: ").strip()

if not os.path.exists(f"cloud_fhe_result_{input_cccd}.bin"):
    print(f"[-] Không tìm thấy kết quả tính toán FHE cho bệnh nhân có CCCD: {input_cccd}")
    exit()

X_pass_aes = getpass.getpass(f">> [Ẩn] Nhập mật khẩu AES để tải Bản sao đối chứng: ")
X_pass_fhe = getpass.getpass(f">> [Ẩn] Nhập mật khẩu FHE để giải mã kết quả AI: ")

try:
    # ---------------------------------------------------------
    # BƯỚC 1: KHU VỰC BỘ ĐỆM TÍNH TOÁN FHE (BUFFER ZONE)
    # ---------------------------------------------------------
    fhe_decrypt_cipher = get_aes_key(X_pass_fhe, b'salt_for_fhe_key')
    with open(f"locked_fhe_sk_{input_cccd}.enc", "rb") as f:
        unlocked_sk_bytes = fhe_decrypt_cipher.decrypt(f.read())
        
    full_context = ts.context_from(unlocked_sk_bytes)
    with open(f"cloud_fhe_result_{input_cccd}.bin", "rb") as f:
        result_encrypted = ts.ckks_vector_from(full_context, f.read())
        
    final_score = round(result_encrypted.decrypt()[0], 2)
    
    # Đưa dữ liệu vào Bộ đệm tạm thời (RAM) thay vì ghi thẳng ra file
    buffer_zone = {
        "cccd_request": input_cccd,
        "fhe_score": final_score,
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    print(f"\n[*] [BỘ ĐỆM] Đã giải mã kết quả AI thành công. Đang lưu tạm tại Bộ đệm...")


    # ---------------------------------------------------------
    # BƯỚC 2: KHU VỰC BẢN SAO CHỜ XÁC THỰC (REPLICA ZONE)
    # ---------------------------------------------------------
    cipher_local = get_aes_key(X_pass_aes, b'salt_for_patient_file')
    with open("Patient_AES.enc", "rb") as f:
        replica_info = cipher_local.decrypt(f.read()).decode('utf-8')
    
    # Trích xuất CCCD từ bản sao để làm khóa đối chứng
    replica_cccd = ""
    for line in replica_info.strip().split('\n'):
        if "CCCD" in line or "Căn cước" in line:
            replica_cccd = line.split(':')[1].strip()
            break
            
    print(f"[*] [BẢN SAO] Đã tải hồ sơ đối chứng. CCCD ghi nhận trong hồ sơ là: {replica_cccd}")


    # ---------------------------------------------------------
    # BƯỚC 3: QUÁ TRÌNH XÁC THỰC KÉP (AUTHENTICATION)
    # ---------------------------------------------------------
    print("\n" + "-"*50)
    print("      TIẾN HÀNH XÁC THỰC TÍNH TOÀN VẸN DỮ LIỆU")
    print("-"*50)
    
    if buffer_zone["cccd_request"] == replica_cccd:
        print("[+] XÁC THỰC THÀNH CÔNG: Thông tin từ Bộ đệm FHE khớp hoàn toàn với Bản sao.")
        print("[+] Đảm bảo dữ liệu người bệnh không bị thay đổi hay phá hủy.")
        
        # ---------------------------------------------------------
        # BƯỚC 4: GHI ĐÈ VÀ CẬP NHẬT VÀO BẢN GỐC (ORIGINAL STORAGE)
        # ---------------------------------------------------------
        file_ban_goc = f"HoSo_BanGoc_{input_cccd}.txt"
        print(f"\n[*] Đang tiến hành cập nhật vào Khu vực Bản Gốc: '{file_ban_goc}'...")
        
        with open(file_ban_goc, "w", encoding="utf-8") as f:
            f.write("==================================================\n")
            f.write("       HỒ SƠ BỆNH ÁN GỐC (ĐÃ CẬP NHẬT KẾT QUẢ AI)\n")
            f.write("==================================================\n")
            f.write(replica_info.strip() + "\n") # Phục hồi dữ liệu người dùng ban đầu
            f.write("-" * 50 + "\n")
            f.write(f"[CẬP NHẬT MỚI NHẤT LÚC: {buffer_zone['timestamp']}]\n")
            f.write(f"==> Chỉ số nguy cơ đột quỵ (AI): {buffer_zone['fhe_score']} / 100\n")
            
            if buffer_zone['fhe_score'] > 60:
                f.write("=> LƯU Ý: Cần thực hiện các biện pháp can thiệp y tế.\n")
            else:
                f.write("=> LƯU Ý: Duy trì theo dõi sức khỏe bình thường.\n")
            f.write("==================================================\n")

        print("[+] HOÀN TẤT! Toàn bộ quy trình xác thực và cập nhật Bản Gốc đã diễn ra an toàn.")

    else:
        # Nếu ai đó cố tình giả mạo file kết quả FHE của người khác gán cho bệnh nhân này
        print("[-] LỖI XÁC THỰC: Số định danh (CCCD) giữa Bộ đệm và Bản sao KHÔNG KHỚP!")
        print("[-] NGỪNG CẬP NHẬT. Khu vực Bản gốc vẫn được giữ nguyên để bảo vệ an toàn.")

except Exception as e:
    print("[-] SAI MẬT KHẨU HOẶC DỮ LIỆU BỊ CORRUPT! Quá trình xác thực thất bại, ngừng cập nhật bản gốc.")