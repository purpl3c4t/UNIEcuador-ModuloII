import torch
import torch.nn as nn
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

class UndercompleteAutoencoder(nn.Module):
    def __init__(self, input_dim=4, latent_dim=2):
        super(UndercompleteAutoencoder, self).__init__()
        # Encoder: Comprime la telemetría al espacio latente
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 3),
            nn.Tanh(),
            nn.Linear(3, latent_dim),
            nn.Tanh()
        )
        # Decoder: Reconstruye las características originales desde el cuello de botella
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 3),
            nn.Tanh(),
            nn.Linear(3, input_dim)
        )
        
    def forward(self, x):
        z = self.encoder(x)
        x_recon = self.decoder(z)
        return x_recon

def train_and_evaluate():
    data_dir = os.path.dirname(__file__) + '/data'
    train_path = f'{data_dir}/telemetry_baseline.csv'
    test_path = f'{data_dir}/telemetry_test.csv'
    
    if not os.path.exists(train_path):
        from generate_data import generate_telemetry
        generate_telemetry()
        
    df_train = pd.read_csv(train_path)
    features = ['cmd_length', 'shannon_entropy', 'execution_hour', 'process_frequency']
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(df_train[features])
    X_train_tensor = torch.tensor(X_train_scaled, dtype=torch.float32)
    
    model = UndercompleteAutoencoder(input_dim=4, latent_dim=2)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    
    print("--- Entrenando Autoencoder Subcompleto en PyTorch (Telemetría Benigna) ---")
    model.train()
    for epoch in range(60):
        optimizer.zero_grad()
        recon = model(X_train_tensor)
        loss = criterion(recon, X_train_tensor)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 15 == 0:
            print(f"Epoch [{epoch+1}/60] - Loss (MSE): {loss.item():.5f}")
            
    # Guardar modelo y scaler
    torch.save(model.state_dict(), f'{data_dir}/autoencoder_model.pt')
    joblib.dump(scaler, f'{data_dir}/scaler.joblib')
    
    # Calcular umbral al Percentil 99 sobre datos benignos
    model.eval()
    with torch.no_grad():
        recon_train = model(X_train_tensor)
        train_mse = torch.mean((X_train_tensor - recon_train) ** 2, dim=1).numpy()
        threshold_p99 = np.percentile(train_mse, 99.0)
        
    print(f"\n[+] Umbral Estadístico de Reconstrucción (Percentil 99): {threshold_p99:.4f}")
    
    # Evaluación en Test Set
    df_test = pd.read_csv(test_path)
    X_test_scaled = scaler.transform(df_test[features])
    X_test_tensor = torch.tensor(X_test_scaled, dtype=torch.float32)
    
    with torch.no_grad():
        recon_test = model(X_test_tensor)
        test_mse = torch.mean((X_test_tensor - recon_test) ** 2, dim=1).numpy()
        
    df_test['reconstruction_error'] = test_mse
    df_test['pred_anomaly'] = (test_mse >= threshold_p99).astype(int)
    
    print("\n--- REPORTE DE DETECCIÓN (Living off the Land) ---")
    print(classification_report(df_test['label'], df_test['pred_anomaly'], target_names=['Benigno', 'Ataque LotL']))
    print("Matriz de Confusión:")
    print(confusion_matrix(df_test['label'], df_test['pred_anomaly']))
    
    df_test.to_csv(f'{data_dir}/evaluation_results.csv', index=False)
    print(f"\nResultados exportados a: {data_dir}/evaluation_results.csv")

if __name__ == '__main__':
    train_and_evaluate()
