import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

class Synapse(nn.Module):
    def __init__(self, input_size, output_size):
        super(Synapse, self).__init__()
        self.layer1 = nn.Linear(input_size, 128)
        self.layer2 = nn.Linear(128, 64)
        self.output_layer = nn.Linear(64, output_size)

    def forward(self, x):
        x = torch.relu(self.layer1(x))
        x = torch.relu(self.layer2(x))
        x = torch.sigmoid(self.output_layer(x))
        return x

    def predict(self, state):
        self.eval()
        with torch.no_grad():
            return self.forward(torch.tensor(state, dtype=torch.float32))

    def train_brain(self, state, target):
        self.train()
        criterion = nn.MSELoss()
        optimizer = optim.SGD(self.parameters(), lr=0.01)

        state_tensor = torch.tensor(state, dtype=torch.float32)
        target_tensor = torch.tensor(target, dtype=torch.float32)

        optimizer.zero_grad()
        output = self.forward(state_tensor)
        loss = criterion(output, target_tensor)
        loss.backward()
        optimizer.step()
        return loss.item()

    def encode_state(self, tech_stack):
        features = [1 if 'php' in tech_stack else 0,
                    1 if 'mysql' in tech_stack else 0,
                    len(tech_stack)]
        return np.array(features, dtype=np.float32)
