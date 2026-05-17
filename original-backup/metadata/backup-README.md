# 서버 백업 아카이브

## 📅 백업 정보
- **날짜**: $(date)
- **호스트**: $(hostname)
- **사용자**: $(whoami)

## 📂 디렉토리 구조
```
kubernetes/          # K8s 전체 설정 (YAML)
docker-images/       # Docker 이미지 tar.gz 파일들
projects/            # 프로젝트 소스코드
system/              # Shell 히스토리, 설정 파일
logs/                # 시스템 & 애플리케이션 로그
databases/           # DB 덤프 파일
secrets/             # 환경변수, 시크릿
```

## 🔄 복원 방법

### Kubernetes 복원
```bash
kubectl apply -f kubernetes/namespaces.json
for ns in kubernetes/namespaces/*; do
    kubectl apply -f "$ns"
done
```

### Docker 이미지 복원
```bash
for img in docker-images/*.tar.gz; do
    docker load < "$img"
done
```

### 프로젝트 파일 복원
```bash
tar -xzf projects/home-projects.tar.gz -C ~/
```

## ⚠️ 주의사항
- 시크릿 파일은 안전하게 보관
- 데이터베이스 복원 시 버전 확인
- PV/PVC 바인딩 재설정 필요할 수 있음
