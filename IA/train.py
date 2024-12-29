import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score
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

# Prédictions sur le jeu de test
y_pred = model.predict(X_test)

# Vérifiez si c'est un problème binaire ou multiclasses
if len(set(y_test)) == 2:  # Si y_test contient deux classes seulement
    precision = precision_score(y_test, y_pred, average='binary')
    recall = recall_score(y_test, y_pred, average='binary')
    f1 = f1_score(y_test, y_pred, average='binary')
else:  # Si c'est un problème multiclasses
    precision = precision_score(y_test, y_pred, average='macro')
    recall = recall_score(y_test, y_pred, average='macro')
    f1 = f1_score(y_test, y_pred, average='macro')

# Affichage des résultats
print(f"Precision: {precision:.2f}")
print(f"Recall: {recall:.2f}")
print(f"F1 Score: {f1:.2f}")

# Sauvegarde du modèle
joblib.dump(model, "ddos_detector_model.pkl")
