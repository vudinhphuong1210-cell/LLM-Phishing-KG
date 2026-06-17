from abc import ABC, abstractmethod
from typing import List

class IDeduplicator(ABC):
    """Interface định nghĩa giao thức cho các bộ lọc trùng lặp URL."""
    
    @abstractmethod
    def is_duplicate(self, url: str, list_type: str = 'raw') -> bool:
        """
        Kiểm tra xem URL đã từng xuất hiện hay chưa.
        Nếu URL chưa tồn tại (trả về False), hệ thống sẽ tự động ghi nhận URL đó vào bộ nhớ.
        """
        pass

    @abstractmethod
    def is_in_whitelist(self, url: str) -> bool:
        """Kiểm tra xem URL có nằm trong whitelist không."""
        pass

    @abstractmethod
    def filter_and_add_batch(self, urls: List[str], list_type: str = 'raw', read_only: bool = False) -> List[str]:
        """
        Xử lý theo lô (batch): 
        Nhận vào danh sách URL, lọc các URL đã trùng lặp.
        Nếu read_only=False, Insert các URL mới vào DB.
        Trả về danh sách URL chưa tồn tại (mới).
        """
        pass

    @abstractmethod
    def get_existing_in_list(self, urls: List[str], list_type: str) -> set[str]:
        """
        Tra cứu theo lô (batch):
        Nhận vào danh sách URL, tìm kiếm các URL đã tồn tại với list_type chỉ định.
        Trả về set các URL trùng khớp.
        """
        pass
