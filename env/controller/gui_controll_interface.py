class GUIControlInterface:
    # 我觉得我不应该这么写，之后应该得改，先定 agent 的写法吧
    def click(self, x: int, y: int) -> None:
        pass

    def move_to(self, x: int, y: int) -> None:
        pass

    def type_text(self, text: str) -> None:
        pass

    def press_key(self, key: str) -> None:
        pass

    def get_screenshot(self, key: str = None):
        """获取屏幕截图
        
        Args:
            key: 可选的标识符，可用于特定截图操作
            
        Returns:
            PIL.Image: 屏幕截图
        """
        pass