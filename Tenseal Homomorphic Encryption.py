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
print("PHASE 1: CHUYỂN ĐỔI SANG VECTOR SỐ & MÃ HÓA FHE (LOCAL)")
print("="*65)
X_pass_aes = getpass.getpass(">> [Ẩn] Nhập lại mật khẩu AES để mở hồ sơ: ")

try:
    cipher_local = get_aes_key(X_pass_aes, b'salt_for_patient_file')
    with open("Patient_AES.enc", "rb") as f:
        decrypted_text = cipher_local.decrypt(f.read()).decode('utf-8')
    
    print("\n--- CHI TIẾT QUÁ TRÌNH CHUYỂN SANG VECTOR SỐ ---")
    lines = decrypted_text.strip().split('\n')
    
    ngay_sinh_str = lines[2].strip().split(':')[1]
    nam_sinh = int(ngay_sinh_str.split('/')[2])
    tuoi = float(datetime.datetime.now().year - nam_sinh)
    print(f"[*] Phân tích tuổi: NgaySinh({ngay_sinh_str}) -> {tuoi} tuổi")
    
    gioi_tinh_str = lines[3].strip()
    gioi_tinh = 1.0 if "Nam" in gioi_tinh_str else 0.0
    print(f"[*] Phân tích giới tính: {gioi_tinh_str} -> Mã hóa số: {gioi_tinh}")
    
    benh_ly_str = lines[5].strip()
    benh_tim = 1.0 if "HeartAttack" in benh_ly_str else 0.0
    print(f"[*] Phân tích bệnh lý: {benh_ly_str} -> Mã hóa số: {benh_tim}")
    
    patient_vector = [tuoi, gioi_tinh, benh_tim]
    print(f"==> KẾT QUẢ VECTOR: patient_vector = {patient_vector}")
    print("------------------------------------------------\n")
    
    print("[+] Đang khởi tạo hệ thống toán học FHE (Gồm Secret Key & Galois Keys)...")
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.global_scale = 2**40
    context.generate_galois_keys()
    
    encrypted_fhe_data = ts.ckks_vector(context, patient_vector)
    with open("cloud_fhe_data.bin", "wb") as f:
        f.write(encrypted_fhe_data.serialize())
    
    # 1. Lưu trữ Secret Key tại Local bằng AES
    mat_khau_fhe = getpass.getpass(">> [Ẩn] Thiết lập mật khẩu bảo vệ Secret Key FHE: ")
    secret_context = context.serialize(save_secret_key=True)
    fhe_aes_cipher = get_aes_key(mat_khau_fhe, b'salt_for_fhe_key')
    with open("locked_fhe_sk.enc", "wb") as f:
        f.write(fhe_aes_cipher.encrypt(secret_context))
        
    # 2. Xóa Secret Key khỏi Context và xuất Public Context (chứa Galois Keys) ra file cho Cloud
    context.make_context_public() 
    with open("cloud_context.bin", "wb") as f:
        f.write(context.serialize())
        
    print("[+] Đã mã hóa FHE, lưu Secret Key (Local) và xuất Public Context (Cloud) thành công!\n")

except Exception as e:
    print("[-] SAI MẬT KHẨU AES hoặc có lỗi xảy ra!")
    print(e)
    exit()


print("="*65)
print("PHASE 2: HÀM TÍNH TOÁN TRÊN ĐÁM MÂY (CLOUD COMPUTING)")
print("="*65)
# Cloud không biết gì về môi trường Local, chỉ nạp Context và Data từ file đã được "upload"
with open("cloud_context.bin", "rb") as f:
    cloud_context = ts.context_from(f.read())
print(f"[*] Cloud xác nhận đã nhận được Galois Key: {cloud_context.has_galois_keys()}")
with open("cloud_fhe_data.bin", "rb") as f:
    cloud_data = ts.ckks_vector_from(cloud_context, f.read())

print("--- CHI TIẾT CÔNG THỨC AI TRÊN CLOUD ---")
print("[*] Công thức tính Điểm nguy cơ đột quỵ:")
print("    Điểm = (Tuổi * W1) + (Giới tính * W2) + (Bệnh tim * W3)")
cloud_weights = [0.5, 10.0, 50.0]
print(f"[*] Đám mây nạp trọng số (Weights): {cloud_weights}")
print("[*] Đám mây thực thi hàm: cloud_result = cloud_data.dot(cloud_weights)")
print("----------------------------------------\n")

cloud_result = cloud_data.dot(cloud_weights)
with open("cloud_fhe_result.bin", "wb") as f:
    f.write(cloud_result.serialize())
print("[+] Cloud tính toán xong, trả về file 'cloud_fhe_result.bin'.\n")


print("="*65)
print("PHASE 3: GIẢI MÃ KẾT QUẢ TẠI LOCAL")
print("="*65)
X_pass_fhe = getpass.getpass(">> [Ẩn] Nhập mật khẩu bảo vệ FHE để xem kết quả: ")

try:
    fhe_decrypt_cipher = get_aes_key(X_pass_fhe, b'salt_for_fhe_key')
    with open("locked_fhe_sk.enc", "rb") as f:
        unlocked_sk_bytes = fhe_decrypt_cipher.decrypt(f.read())
        
    full_context = ts.context_from(unlocked_sk_bytes)
    with open("cloud_fhe_result.bin", "rb") as f:
        result_encrypted = ts.ckks_vector_from(full_context, f.read())
        
    final_score = result_encrypted.decrypt()
    
    # ---------------------------------------------------------
    # PHẦN HIỂN THỊ KẾT QUẢ
    # ---------------------------------------------------------
    print("\n\n" + "*"*50)
    print("      BÁO CÁO Y TẾ & ĐÁNH GIÁ TỪ ĐÁM MÂY")
    print("*"*50)
    print("[THÔNG TIN HỒ SƠ BỆNH NHÂN]")
    print(decrypted_text.strip()) 
    print("-" * 50)
    print(f"[ĐÁNH GIÁ TỪ AI ĐÁM MÂY (ĐÃ GIẢI MÃ FHE)]")
    print(f"==> Nguy cơ đột quỵ: {round(final_score[0], 2)} / 100")
    print("*"*50 + "\n")

except Exception as e:
    print("[-] SAI MẬT KHẨU FHE! Không thể giải mã.")
    print("[-] SAI MẬT KHẨU FHE! Không thể giải mã.")
