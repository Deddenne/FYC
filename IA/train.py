import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Chargement des données
# Exemple : données avec colonnes ['ip_count', 'packet_rate', 'is_ddos']
data = pd.read_csv("network_traffic.csv")

# Séparer les caractéristiques (X) et la cible (y)
X = data[['ip_count', 'packet_rate']]  # Nombre de connexions et taux de paquets
y = data['is_ddos']  # 0 = normal, 1 = attaque

# Division en ensembles d'entraînement et de test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Entraînement du modèle
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Évaluation
accuracy = model.score(X_test, y_test)
print(f"Model Accuracy: {accuracy:.2f}")

# Sauvegarde du modèle
joblib.dump(model, "ddos_detector_model.pkl")
