### 3. Focused Analysis

```bash
# Scan specific parts by using ignore patterns
python -m src.main \
  --local-path ./my-app \
  --extra-ignore-dirs "frontend,mobile,docs,tests"
```

### 4. Custom PyTorch Embedding Configuration

```bash
# Use a specific embedding model with custom settings
python -m src.main \
  --local-path ./my-app \
  --pytorch-model "all-mpnet-base-v2" \
  --pytorch-device "cuda" \
  --pytorch-dimension 768 \
  --verbose
```
