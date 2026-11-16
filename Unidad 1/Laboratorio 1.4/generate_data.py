import pandas as pd
import os

def generate_insider_threat_data():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    out_file = os.path.join(data_dir, "insider_audit_events.csv")
    
    # Secuencia temporal forense del caso de estudio (Camino Crítico del Insider)
    events = [
        {
            "timestamp": "2026-11-15 08:30:15",
            "user": "maria.gonzalez",
            "event_id": 4624,
            "logon_type": 2,
            "action": "Interactive_Logon",
            "resource": "WS_Finanzas_02",
            "bytes_transferred": 0,
            "hour": 8.50,
            "is_off_hours": 0,
            "is_sensitive": 0,
            "staging_detected": 0
        },
        {
            "timestamp": "2026-11-15 11:15:22",
            "user": "maria.gonzalez",
            "event_id": 4663,
            "logon_type": 2,
            "action": "File_Read",
            "resource": "Finanzas_Presupuesto.xlsx",
            "bytes_transferred": 250000,
            "hour": 11.25,
            "is_off_hours": 0,
            "is_sensitive": 0,
            "staging_detected": 0
        },
        {
            "timestamp": "2026-11-15 15:45:10",
            "user": "maria.gonzalez",
            "event_id": 4663,
            "logon_type": 2,
            "action": "File_Read",
            "resource": "Clientes_VIP_Reporte.csv",
            "bytes_transferred": 1850000,
            "hour": 15.75,
            "is_off_hours": 0,
            "is_sensitive": 1,
            "staging_detected": 0
        },
        {
            "timestamp": "2026-11-16 01:45:00",
            "user": "maria.gonzalez",
            "event_id": 4624,
            "logon_type": 10,
            "action": "Remote_RDP_Logon",
            "resource": "WS_Finanzas_02",
            "bytes_transferred": 0,
            "hour": 1.75,
            "is_off_hours": 1,
            "is_sensitive": 0,
            "staging_detected": 0
        },
        {
            "timestamp": "2026-11-16 02:05:30",
            "user": "maria.gonzalez",
            "event_id": 4688,
            "logon_type": 10,
            "action": "Process_Create_Archiver",
            "resource": "AppData_Local_Temp_backup.7z",
            "bytes_transferred": 15000000,
            "hour": 2.08,
            "is_off_hours": 1,
            "is_sensitive": 1,
            "staging_detected": 1
        },
        {
            "timestamp": "2026-11-16 02:20:45",
            "user": "maria.gonzalez",
            "event_id": 4663,
            "logon_type": 10,
            "action": "Cloud_Transfer",
            "resource": "External_Cloud_Storage",
            "bytes_transferred": 15000000,
            "hour": 2.33,
            "is_off_hours": 1,
            "is_sensitive": 1,
            "staging_detected": 1
        }
    ]
    
    df = pd.DataFrame(events)
    df.to_csv(out_file, index=False)
    print(f"Lab 4: Dataset de auditoría forense generado exitosamente en:\n -> {out_file}")
    return df

if __name__ == "__main__":
    generate_insider_threat_data()
