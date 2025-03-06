"""
基于图像的评估器 - 使用图像分析验证任务执行状态
适用于Docker等无法直接访问UI元素树的环境
"""

import os
import time
import numpy as np
from typing import Dict, List, Any, Optional, Callable, Tuple
from PIL import Image, ImageChops, ImageFilter

from evaluator.base_evaluator import BaseEvaluator


class ImageBasedEvaluator(BaseEvaluator):
    """基于图像分析的评估器，使用图像特征和区域分析进行验证"""

    def __init__(self, task_name: str, reference_dir: str = 'evaluator/references'):
        """
        初始化图像评估器
        
        Args:
            task_name: 任务名称
            reference_dir: 参考图像目录
        """
        super().__init__(task_name)
        self.reference_dir = reference_dir
        self.previous_screenshots = {}  # 缓存之前的截图
        self.reference_images = {}  # 缓存参考图像
        
        # 确保参考图像目录存在
        os.makedirs(self.reference_dir, exist_ok=True)
        
    def _check_condition(self, context: Any, condition: Dict) -> bool:
        """
        检查图像条件是否满足
        
        Args:
            context: 评估上下文(截图)
            condition: 条件描述
            
        Returns:
            bool: 条件是否满足
        """
        if not isinstance(context, Image.Image):
            self.log("上下文不是有效的图像")
            return False
            
        condition_type = condition.get('type', 'unknown')
        
        if condition_type == 'reference_similarity':
            return self._check_reference_similarity(
                context, 
                condition.get('reference_name', ''),
                condition.get('threshold', 0.7),
                condition.get('region', None)
            )
            
        elif condition_type == 'region_brightness':
            return self._check_region_brightness(
                context,
                condition.get('region', (0, 0, 100, 100)),
                condition.get('min_brightness', 0),
                condition.get('max_brightness', 255)
            )
            
        elif condition_type == 'region_change':
            return self._check_region_change(
                context,
                condition.get('previous_step', ''),
                condition.get('region', None),
                condition.get('threshold', 0.1)
            )
            
        elif condition_type == 'color_presence':
            return self._check_color_presence(
                context,
                condition.get('rgb', (255, 255, 255)),
                condition.get('tolerance', 30),
                condition.get('region', None),
                condition.get('min_pixels', 100)
            )
            
        self.log(f"未知的条件类型: {condition_type}")
        return False
        
    def _get_reference_image(self, reference_name: str) -> Optional[Image.Image]:
        """
        获取参考图像
        
        Args:
            reference_name: 参考图像名称
            
        Returns:
            Optional[Image.Image]: 参考图像
        """
        if reference_name in self.reference_images:
            return self.reference_images[reference_name]
            
        # 尝试加载参考图像
        reference_path = os.path.join(self.reference_dir, f"{reference_name}.png")
        if not os.path.exists(reference_path):
            self.log(f"参考图像不存在: {reference_path}")
            return None
            
        try:
            image = Image.open(reference_path)
            self.reference_images[reference_name] = image
            return image
        except Exception as e:
            self.log(f"加载参考图像失败: {str(e)}")
            return None
            
    def save_reference(self, image: Image.Image, reference_name: str) -> bool:
        """
        保存参考图像
        
        Args:
            image: 要保存的图像
            reference_name: 参考图像名称
            
        Returns:
            bool: 是否保存成功
        """
        reference_path = os.path.join(self.reference_dir, f"{reference_name}.png")
        try:
            image.save(reference_path)
            self.reference_images[reference_name] = image
            self.log(f"已保存参考图像: {reference_path}")
            return True
        except Exception as e:
            self.log(f"保存参考图像失败: {str(e)}")
            return False
            
    def _calculate_similarity(self, img1: Image.Image, img2: Image.Image) -> float:
        """
        计算两个图像的相似度
        
        Args:
            img1: 第一个图像
            img2: 第二个图像
            
        Returns:
            float: 相似度(0-1)
        """
        # 确保尺寸一致
        if img1.size != img2.size:
            img2 = img2.resize(img1.size)
            
        # 计算差异
        diff = ImageChops.difference(img1.convert('RGB'), img2.convert('RGB'))
        
        # 计算差异程度
        stat = diff.convert('L').getdata()
        diff_ratio = sum(stat) / (img1.width * img1.height * 255)
        
        # 转换为相似度
        return 1.0 - diff_ratio
        
    def _crop_region(self, image: Image.Image, region: Optional[Tuple[int, int, int, int]]) -> Image.Image:
        """
        裁剪图像区域
        
        Args:
            image: 原始图像
            region: 区域坐标(x, y, width, height)，None表示整个图像
            
        Returns:
            Image.Image: 裁剪后的图像
        """
        if region is None:
            return image
            
        x, y, width, height = region
        return image.crop((x, y, x + width, y + height))
        
    def _check_reference_similarity(self, image: Image.Image, reference_name: str, 
                                   threshold: float = 0.7, 
                                   region: Optional[Tuple[int, int, int, int]] = None) -> bool:
        """
        检查图像与参考图像的相似度
        
        Args:
            image: 当前图像
            reference_name: 参考图像名称
            threshold: 相似度阈值
            region: 要比较的区域
            
        Returns:
            bool: 是否达到相似度阈值
        """
        reference = self._get_reference_image(reference_name)
        if reference is None:
            return False
            
        # 裁剪区域
        current = self._crop_region(image, region)
        ref = self._crop_region(reference, region)
        
        # 计算相似度
        similarity = self._calculate_similarity(current, ref)
        self.log(f"与参考图像 {reference_name} 的相似度: {similarity:.4f}")
        
        return similarity >= threshold
        
    def _check_region_brightness(self, image: Image.Image, 
                               region: Tuple[int, int, int, int],
                               min_brightness: int = 0, 
                               max_brightness: int = 255) -> bool:
        """
        检查区域亮度是否在指定范围内
        
        Args:
            image: 当前图像
            region: 要检查的区域(x, y, width, height)
            min_brightness: 最小亮度
            max_brightness: 最大亮度
            
        Returns:
            bool: 亮度是否在范围内
        """
        # 裁剪区域
        region_img = self._crop_region(image, region)
        
        # 计算平均亮度
        grayscale = region_img.convert('L')
        mean_brightness = sum(grayscale.getdata()) / (region_img.width * region_img.height)
        
        self.log(f"区域 {region} 的平均亮度: {mean_brightness:.2f}")
        
        return min_brightness <= mean_brightness <= max_brightness
        
    def _check_region_change(self, image: Image.Image, 
                           previous_step: str,
                           region: Optional[Tuple[int, int, int, int]] = None,
                           threshold: float = 0.1) -> bool:
        """
        检查区域相对于之前截图是否有变化
        
        Args:
            image: 当前图像
            previous_step: 之前步骤的名称
            region: 要检查的区域
            threshold: 变化阈值
            
        Returns:
            bool: 是否有显著变化
        """
        if previous_step not in self.previous_screenshots:
            self.log(f"未找到之前的截图: {previous_step}")
            return False
            
        previous = self.previous_screenshots[previous_step]
        
        # 裁剪区域
        current = self._crop_region(image, region)
        prev = self._crop_region(previous, region)
        
        # 确保尺寸一致
        if current.size != prev.size:
            prev = prev.resize(current.size)
            
        # 计算差异
        diff = ImageChops.difference(current.convert('RGB'), prev.convert('RGB'))
        diff_ratio = sum(diff.convert('L').getdata()) / (current.width * current.height * 255)
        
        self.log(f"与步骤 {previous_step} 的区域变化率: {diff_ratio:.4f}")
        
        return diff_ratio >= threshold
        
    def _check_color_presence(self, image: Image.Image, 
                             rgb: Tuple[int, int, int],
                             tolerance: int = 30,
                             region: Optional[Tuple[int, int, int, int]] = None,
                             min_pixels: int = 100) -> bool:
        """
        检查区域是否包含特定颜色
        
        Args:
            image: 当前图像
            rgb: 目标RGB颜色
            tolerance: 颜色容差
            region: 要检查的区域
            min_pixels: 最小匹配像素数
            
        Returns:
            bool: 是否包含足够的匹配像素
        """
        # 裁剪区域
        region_img = self._crop_region(image, region)
        
        # 转换为numpy数组进行颜色匹配
        try:
            import numpy as np
            r, g, b = rgb
            img_array = np.array(region_img.convert('RGB'))
            
            # 创建颜色掩码
            r_mask = np.abs(img_array[:,:,0] - r) <= tolerance
            g_mask = np.abs(img_array[:,:,1] - g) <= tolerance
            b_mask = np.abs(img_array[:,:,2] - b) <= tolerance
            color_mask = r_mask & g_mask & b_mask
            
            # 计算匹配像素数
            matching_pixels = np.sum(color_mask)
            
            self.log(f"颜色 {rgb} 的匹配像素数: {matching_pixels}")
            
            return matching_pixels >= min_pixels
            
        except ImportError:
            self.log("未安装numpy，使用替代方法检查颜色")
            
            # 替代方法：逐像素检查
            pixels = list(region_img.convert('RGB').getdata())
            matching_pixels = 0
            
            for p_r, p_g, p_b in pixels:
                if (abs(p_r - r) <= tolerance and 
                    abs(p_g - g) <= tolerance and 
                    abs(p_b - b) <= tolerance):
                    matching_pixels += 1
                    
                if matching_pixels >= min_pixels:
                    return True
                    
            self.log(f"颜色 {rgb} 的匹配像素数: {matching_pixels}")
            return False
            
    def store_screenshot(self, step_name: str, screenshot: Image.Image) -> None:
        """
        存储步骤的截图，用于后续比较
        
        Args:
            step_name: 步骤名称
            screenshot: 截图
        """
        self.previous_screenshots[step_name] = screenshot.copy()
        
    def evaluate_step(self, step_name: str, context: Any = None) -> bool:
        """
        重写评估步骤方法，添加截图存储功能
        
        Args:
            step_name: 步骤名称
            context: 评估上下文(截图)
            
        Returns:
            bool: 步骤是否成功
        """
        result = super().evaluate_step(step_name, context)
        
        # 如果上下文是图像，存储它
        if isinstance(context, Image.Image):
            self.store_screenshot(step_name, context)
            
        return result