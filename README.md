SDN Intrusion Detection System using LSTM
This project implements an Intrusion Detection System (IDS) for Software Defined Networking (SDN) using a Long Short-Term Memory (LSTM) model. The system is trained on the InSDN dataset and performs multi-class classification to detect different types of network attacks.

Features
Dataset: InSDN (Software Defined Networking Intrusion Detection Dataset)

Selected 12 most important features using SelectKBest from the original 82 features.

Deep Learning Model: LSTM (Long Short-Term Memory)

8-class classification for SDN traffic.

Dataset Information
Original Features: 82

Selected Features (Top 12):

Src IP

Dst IP

Dst Port

Flow Duration

Flow Pkts/s

Flow IAT Mean

Bwd IAT Tot

Bwd IAT Mean

Bwd IAT Max

Bwd Header Len

Bwd Pkts/s

Init Bwd Win Byts

Target Labels (8 attack classes):

Normal

DoS

DDoS

Probe

R2L

U2R

MITM

