핵심은 distance vector 저장이다.

  struct RouteEntry {
    uint32_t nextHop;
    Size metric;
    int port;  // 전송에 사용될 포트
  };
  std::unordered_map<uint32_t, RouteEntry> routingTable;

나는 이런 구조를 만들어 저장했다. routingTable의 key는 목표로 하는 ip 주소이고, nextHop은 거기로 가기 위해 현재 어느 이웃한 라우터로 가야하는지이다.

처음에는 자기의 ip 주소를 모두 거리 0으로 세팅하여 테이블에 저장한다. 그리고 request를 보낸다.
request를 받으면 response를 보내면 된다. request를 받지 않아도, 내 테이블에 변경 사항이 있으면 주기적으로 response를 보낸다.

그럼 response에는 뭐가 있느냐? 
그냥 내 테이블을 통채로 보내는 것이다. 형식만 packet 형식으로 바꿔서.
그럼 response를 받은 측에서는 새로운 ip 로 가는 경로가 담겨있다면 추가하고, 이미 있는 ip라면 기존보다 더 짧은 경우에만 추가한다.
반복한다.
끝!
