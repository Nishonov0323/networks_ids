import pandas as pd
import numpy as np

# Load the raw packet data
input_file = 'C:/Users/user/Documents/raw_computer_traffic.csv'
df = pd.read_csv(input_file)

# Dastlabki qatorlar sonini chop etish
print(f"Dastlabki qatorlar soni: {len(df)}")

# To‘g‘rilash: frame.time ni tozalash va formatni moslashtirish
df['frame.time'] = df['frame.time'].str.replace('West Asia Standard Time', '').str.strip()
df['frame.time'] = df['frame.time'].str.replace(',', '')
df['frame.time'] = df['frame.time'].str.replace(r'(\.\d{6})\d+', r'\1', regex=True)

# Vaqtni datetime ga o‘tkazish
try:
    df['frame.time'] = pd.to_datetime(df['frame.time'], format='%b %d %Y %H:%M:%S.%f')
except ValueError as e:
    print(f"Xato: Vaqt formatini o'zgartirishda muammo: {e}")
    print("Namuna vaqtlar:")
    print(df['frame.time'].head())
    raise

# Ma'lumotlarni tozalash
# IP manzillarni tozalash: bo'sh yoki noto'g'ri qiymatlarni saqlashga harakat qilamiz
df['ip.src'] = df['ip.src'].fillna('0.0.0.0').astype(str).replace('nan', '0.0.0.0')
df['ip.dst'] = df['ip.dst'].fillna('0.0.0.0').astype(str).replace('nan', '0.0.0.0')
df['ip.proto'] = pd.to_numeric(df['ip.proto'], errors='coerce').fillna(0).astype(int)
df['tcp.srcport'] = pd.to_numeric(df['tcp.srcport'], errors='coerce').fillna(0).astype(int)
df['tcp.dstport'] = pd.to_numeric(df['tcp.dstport'], errors='coerce').fillna(0).astype(int)
df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce').fillna(0).astype(float)
df['frame.time_delta'] = pd.to_numeric(df['frame.time_delta'], errors='coerce').fillna(0).astype(float)
df['tcp.flags'] = df['tcp.flags'].astype(str).fillna('0x0000')
df['tcp.window_size'] = pd.to_numeric(df['tcp.window_size'], errors='coerce').fillna(0).astype(float)

# Tozalashdan keyingi qatorlar soni
print(f"Tozalashdan keyin qatorlar soni: {len(df)}")

# Foydasiz qatorlarni filtrlashni yumshatish
# Faqat ip.src va ip.dst ikkalasi ham 0.0.0.0 bo'lsa olib tashlaymiz
invalid_rows = (df['ip.src'] == '0.0.0.0') & (df['ip.dst'] == '0.0.0.0')
if invalid_rows.any():
    print(f"Foydasiz qatorlar topildi ({invalid_rows.sum()} ta qator):")
    print(df[invalid_rows][['ip.src', 'ip.dst', 'ip.proto', 'tcp.srcport', 'tcp.dstport']].head())
    df = df[~invalid_rows]
    print("Foydasiz qatorlar o‘chirildi.")
else:
    print("Foydasiz qatorlar topilmadi.")

# Filtrlashdan keyingi qatorlar soni
print(f"Filtrlashdan keyin qatorlar soni: {len(df)}")

# Agar DataFrame bo‘sh bo‘lsa, jarayonni to‘xtatish
if df.empty:
    raise ValueError("DataFrame bo‘sh! Foydasiz qatorlardan keyin hech qanday ma'lumot qolmadi.")


# Flow ID yaratish (string sifatida saqlash, noyob qilish uchun frame.time qo'shamiz)
def create_flow_id(row):
    src_ip = str(row['ip.src']).strip() if pd.notnull(row['ip.src']) and row['ip.src'] != 'nan' else '0.0.0.0'
    dst_ip = str(row['ip.dst']).strip() if pd.notnull(row['ip.dst']) and row['ip.dst'] != 'nan' else '0.0.0.0'

    if not src_ip or src_ip == 'nan':
        src_ip = '0.0.0.0'
    if not dst_ip or dst_ip == 'nan':
        dst_ip = '0.0.0.0'

    proto = int(row['ip.proto']) if pd.notnull(row['ip.proto']) else 0
    src_port = int(row['tcp.srcport']) if pd.notnull(row['tcp.srcport']) else -1
    dst_port = int(row['tcp.dstport']) if pd.notnull(row['tcp.dstport']) else -1

    # Noyob qilish uchun frame.time qo'shamiz
    timestamp = str(row['frame.time'])
    return f"{src_ip}:{dst_ip}:{proto}:{src_port}:{dst_port}:{timestamp}"


# Flow ID yaratish
df['flow_id'] = df.apply(create_flow_id, axis=1)

# Flow ID yaratishdan keyingi qatorlar soni
print(f"Flow ID yaratishdan keyin qatorlar soni: {len(df)}")

# Group packets by flow
flows = df.groupby('flow_id')

# Guruhlar sonini chop etish
print(f"Guruhlar soni: {len(flows)}")

# Initialize a list to store processed flows
flow_data = []

for flow_id, flow_df in flows:
    # Flow ID ni qayta parse qilish (string dan tuple ga)
    try:
        parts = flow_id.split(':')
        src_ip, dst_ip, proto, src_port, dst_port = parts[0], parts[1], int(parts[2]), int(parts[3]), int(parts[4])
    except ValueError as e:
        print(f"Flow ID parse qilishda xatolik: {flow_id}")
        raise ValueError("Flow ID noto‘g‘ri formatda!")

    # Split forward and backward packets
    flow_df['is_forward'] = flow_df.apply(lambda row: row['ip.src'] < row['ip.dst'], axis=1)
    fwd_packets = flow_df[flow_df['is_forward']]
    bwd_packets = flow_df[~flow_df['is_forward']]

    # Timestamps
    timestamps = flow_df['frame.time']
    flow_duration = (timestamps.max() - timestamps.min()).total_seconds() * 1000000  # in microseconds

    # Packet counts
    total_fwd_packets = len(fwd_packets)
    total_backward_packets = len(bwd_packets)

    # Packet lengths
    fwd_lengths = fwd_packets['frame.len'].astype(float)
    bwd_lengths = bwd_packets['frame.len'].astype(float)
    all_lengths = flow_df['frame.len'].astype(float)

    # Forward packet length stats
    fwd_packets_length_total = fwd_lengths.sum()
    fwd_packet_length_max = fwd_lengths.max() if total_fwd_packets > 0 else 0
    fwd_packet_length_min = fwd_lengths.min() if total_fwd_packets > 0 else 0
    fwd_packet_length_mean = fwd_lengths.mean() if total_fwd_packets > 0 else 0
    fwd_packet_length_std = fwd_lengths.std() if total_fwd_packets > 0 else 0

    # Backward packet length stats
    bwd_packets_length_total = bwd_lengths.sum()
    bwd_packet_length_max = bwd_lengths.max() if total_backward_packets > 0 else 0
    bwd_packet_length_min = bwd_lengths.min() if total_backward_packets > 0 else 0
    bwd_packet_length_mean = bwd_lengths.mean() if total_backward_packets > 0 else 0
    bwd_packet_length_std = bwd_lengths.std() if total_backward_packets > 0 else 0

    # Overall packet length stats
    packet_length_min = all_lengths.min() if len(all_lengths) > 0 else 0
    packet_length_max = all_lengths.max() if len(all_lengths) > 0 else 0
    packet_length_mean = all_lengths.mean() if len(all_lengths) > 0 else 0
    packet_length_std = all_lengths.std() if len(all_lengths) > 0 else 0
    packet_length_variance = all_lengths.var() if len(all_lengths) > 0 else 0

    # Flow rates (convert duration to seconds for rates)
    duration_seconds = flow_duration / 1000000
    duration_seconds = max(duration_seconds, 1e-6)  # Avoid division by zero
    flow_bytes_s = (fwd_packets_length_total + bwd_packets_length_total) / duration_seconds
    flow_packets_s = (total_fwd_packets + total_backward_packets) / duration_seconds
    fwd_packets_s = total_fwd_packets / duration_seconds
    bwd_packets_s = total_backward_packets / duration_seconds

    # Inter-arrival times (IAT)
    time_deltas = flow_df['frame.time_delta'].astype(float)
    flow_iat_mean = time_deltas.mean() if len(time_deltas) > 0 else 0
    flow_iat_std = time_deltas.std() if len(time_deltas) > 0 else 0
    flow_iat_max = time_deltas.max() if len(time_deltas) > 0 else 0
    flow_iat_min = time_deltas.min() if len(time_deltas) > 0 else 0

    # Forward IAT
    fwd_deltas = fwd_packets['frame.time_delta'].astype(float)
    fwd_iat_total = fwd_deltas.sum() if len(fwd_deltas) > 0 else 0
    fwd_iat_mean = fwd_deltas.mean() if len(fwd_deltas) > 0 else 0
    fwd_iat_std = fwd_deltas.std() if len(fwd_deltas) > 0 else 0
    fwd_iat_max = fwd_deltas.max() if len(fwd_deltas) > 0 else 0
    fwd_iat_min = fwd_deltas.min() if len(fwd_deltas) > 0 else 0

    # Backward IAT
    bwd_deltas = bwd_packets['frame.time_delta'].astype(float)
    bwd_iat_total = bwd_deltas.sum() if len(bwd_deltas) > 0 else 0
    bwd_iat_mean = bwd_deltas.mean() if len(bwd_deltas) > 0 else 0
    bwd_iat_std = bwd_deltas.std() if len(bwd_deltas) > 0 else 0
    bwd_iat_max = bwd_deltas.max() if len(bwd_deltas) > 0 else 0
    bwd_iat_min = bwd_deltas.min() if len(bwd_deltas) > 0 else 0


    # TCP Flags (parse tcp.flags)
    def count_flags(flag_df, flag_value):
        return flag_df['tcp.flags'].astype(str).str.contains(flag_value, na=False).sum()


    # Flag values (hex): FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40
    fin_flag_count = count_flags(flow_df, '0x0*1')  # FIN flag
    syn_flag_count = count_flags(flow_df, '0x0*2')  # SYN flag
    rst_flag_count = count_flags(flow_df, '0x0*4')  # RST flag
    psh_flag_count = count_flags(flow_df, '0x0*8')  # PSH flag
    ack_flag_count = count_flags(flow_df, '0x0*10')  # ACK flag
    urg_flag_count = count_flags(flow_df, '0x0*20')  # URG flag
    ece_flag_count = count_flags(flow_df, '0x0*40')  # ECE flag
    fwd_psh_flags = count_flags(fwd_packets, '0x0*8')  # PSH flags in forward direction

    # Header lengths (approximate: IP header + TCP header)
    fwd_header_length = total_fwd_packets * 40  # Simplified
    bwd_header_length = total_backward_packets * 40

    # Other features
    down_up_ratio = total_backward_packets / max(total_fwd_packets, 1)
    avg_packet_size = (fwd_packets_length_total + bwd_packets_length_total) / max(
        total_fwd_packets + total_backward_packets, 1)
    avg_fwd_segment_size = fwd_packet_length_mean
    avg_bwd_segment_size = bwd_packet_length_mean

    # Subflow (simplified as the entire flow)
    subflow_fwd_packets = total_fwd_packets
    subflow_fwd_bytes = fwd_packets_length_total
    subflow_bwd_packets = total_backward_packets
    subflow_bwd_bytes = bwd_packets_length_total

    # Window sizes
    init_fwd_win_bytes = fwd_packets['tcp.window_size'].astype(float).iloc[0] if len(fwd_packets) > 0 else 0
    init_bwd_win_bytes = bwd_packets['tcp.window_size'].astype(float).iloc[0] if len(bwd_packets) > 0 else 0

    # Forward active data packets (packets with payload)
    fwd_act_data_packets = len(fwd_packets[fwd_packets['frame.len'].astype(float) > 40])
    fwd_seg_size_min = 20  # Minimum TCP header size (simplified)

    # Active and idle times (approximate)
    deltas = time_deltas[time_deltas > 0]
    active_threshold = 1.0  # 1 second threshold for active periods
    active_periods = deltas[deltas < active_threshold]
    idle_periods = deltas[deltas >= active_threshold]
    active_mean = active_periods.mean() if len(active_periods) > 0 else 0
    active_std = active_periods.std() if len(active_periods) > 0 else 0
    active_max = active_periods.max() if len(active_periods) > 0 else 0
    active_min = active_periods.min() if len(active_periods) > 0 else 0
    idle_mean = idle_periods.mean() if len(idle_periods) > 0 else 0
    idle_std = idle_periods.std() if len(idle_periods) > 0 else 0
    idle_max = idle_periods.max() if len(idle_periods) > 0 else 0
    idle_min = idle_periods.min() if len(idle_periods) > 0 else 0

    # Create a dictionary for the flow with updated feature names in Title Case
    flow_entry = {
        'Protocol': float(proto),
        'Flow Duration': flow_duration,
        'Total Fwd Packets': float(total_fwd_packets),
        'Total Backward Packets': float(total_backward_packets),
        'Fwd Packets Length Total': float(fwd_packets_length_total),
        'Bwd Packets Length Total': float(bwd_packets_length_total),
        'Fwd Packet Length Max': float(fwd_packet_length_max),
        'Fwd Packet Length Min': float(fwd_packet_length_min),
        'Fwd Packet Length Mean': float(fwd_packet_length_mean),
        'Fwd Packet Length Std': float(fwd_packet_length_std),
        'Bwd Packet Length Max': float(bwd_packet_length_max),
        'Bwd Packet Length Min': float(bwd_packet_length_min),
        'Bwd Packet Length Mean': float(bwd_packet_length_mean),
        'Bwd Packet Length Std': float(bwd_packet_length_std),
        'Flow Bytes/s': float(flow_bytes_s),
        'Flow Packets/s': float(flow_packets_s),
        'Flow IAT Mean': float(flow_iat_mean),
        'Flow IAT Std': float(flow_iat_std),
        'Flow IAT Max': float(flow_iat_max),
        'Flow IAT Min': float(flow_iat_min),
        'Fwd IAT Total': float(fwd_iat_total),
        'Fwd IAT Mean': float(fwd_iat_mean),
        'Fwd IAT Std': float(fwd_iat_std),
        'Fwd IAT Max': float(fwd_iat_max),
        'Fwd IAT Min': float(fwd_iat_min),
        'Bwd IAT Total': float(bwd_iat_total),
        'Bwd IAT Mean': float(bwd_iat_mean),
        'Bwd IAT Std': float(bwd_iat_std),
        'Bwd IAT Max': float(bwd_iat_max),
        'Bwd IAT Min': float(bwd_iat_min),
        'Fwd PSH Flags': float(fwd_psh_flags),
        'Fwd Header Length': float(fwd_header_length),
        'Bwd Header Length': float(bwd_header_length),
        'Fwd Packets/s': float(fwd_packets_s),
        'Bwd Packets/s': float(bwd_packets_s),
        'Packet Length Min': float(packet_length_min),
        'Packet Length Max': float(packet_length_max),
        'Packet Length Mean': float(packet_length_mean),
        'Packet Length Std': float(packet_length_std),
        'Packet Length Variance': float(packet_length_variance),
        'FIN Flag Count': float(fin_flag_count),
        'SYN Flag Count': float(syn_flag_count),
        'RST Flag Count': float(rst_flag_count),
        'PSH Flag Count': float(psh_flag_count),
        'ACK Flag Count': float(ack_flag_count),
        'URG Flag Count': float(urg_flag_count),
        'ECE Flag Count': float(ece_flag_count),
        'Down/Up Ratio': float(down_up_ratio),
        'Avg Packet Size': float(avg_packet_size),
        'Avg Fwd Segment Size': float(avg_fwd_segment_size),
        'Avg Bwd Segment Size': float(avg_bwd_segment_size),
        'Subflow Fwd Packets': float(subflow_fwd_packets),
        'Subflow Fwd Bytes': float(subflow_fwd_bytes),
        'Subflow Bwd Packets': float(subflow_bwd_packets),
        'Subflow Bwd Bytes': float(subflow_bwd_bytes),
        'Init Fwd Win Bytes': float(init_fwd_win_bytes),
        'Init Bwd Win Bytes': float(init_bwd_win_bytes),
        'Fwd Act Data Packets': float(fwd_act_data_packets),
        'Fwd Seg Size Min': float(fwd_seg_size_min),
        'Active Mean': float(active_mean),
        'Active Std': float(active_std),
        'Active Max': float(active_max),
        'Active Min': float(active_min),
        'Idle Mean': float(idle_mean),
        'Idle Std': float(idle_std),
        'Idle Max': float(idle_max),
        'Idle Min': float(idle_min),
    }

    flow_data.append(flow_entry)

# Convert to DataFrame
network_flows = pd.DataFrame(flow_data)

# Handle missing values and invalid values
network_flows = network_flows.fillna(0)
network_flows.replace([float('inf'), -float('inf')], 0, inplace=True)

# Yakuniy qatorlar soni
print(f"Yakuniy qatorlar soni (network_flows): {len(network_flows)}")

# Save to CSV
network_flows.to_csv('C:\\Users\\user\\PycharmProjects\\Intrusion-Detection-System-Using-Machine-Learning'
                     '\\network_ids\\ml_models\\data\\test_x_2.csv', index=False)

print("CSV fayli muvaffaqiyatli yaratildi: ml_models/data/test_x_2.csv")
