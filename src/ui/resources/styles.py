"""QSS 样式表 — 使用动态颜色模板"""

STYLE_TEMPLATE = """
QMainWindow, QDialog {{
    background-color: {bg_primary};
}}
QWidget {{
    font-family: {font_family};
    font-size: 13px;
    color: {text_primary};
}}
QScrollArea, QScrollArea > QWidget > QWidget {{
    background: {bg_primary};
    border: none;
}}
QLineEdit, QTextEdit {{
    border: 1px solid {border};
    border-radius: 8px;
    padding: 7px 11px;
    background: {bg_input};
    color: {text_primary};
    selection-background-color: {accent};
}}
QLineEdit:focus, QTextEdit:focus {{
    border: 2px solid {accent};
    padding: 6px 10px;
}}
QPushButton {{
    border: 1px solid {border};
    border-radius: 8px;
    padding: 6px 16px;
    background: {btn_bg};
    color: {text_primary};
    min-height: 28px;
}}
QPushButton:disabled {{
    color: {text_muted};
    background: {bg_secondary};
}}
QPushButton:hover {{
    background: {btn_hover};
}}
QPushButton:pressed {{
    background: {btn_pressed};
}}
QPushButton#primaryBtn {{
    background: {accent};
    color: {text_on_accent};
    border: none;
    font-weight: bold;
}}
QPushButton#primaryBtn:hover {{
    background: {accent_hover};
}}
QPushButton#iconBtn {{
    border: none;
    background: transparent;
    padding: 4px;
    font-size: 16px;
    min-width: 0px;
    min-height: 0px;
}}
QPushButton#iconBtn:hover {{
    background: {icon_btn_hover};
    border-radius: 4px;
}}
QComboBox {{
    border: 1px solid {border};
    border-radius: 8px;
    padding: 6px 10px;
    background: {bg_input};
    color: {text_primary};
    min-height: 24px;
}}
QComboBox QAbstractItemView {{
    background: {menu_bg};
    color: {text_primary};
    selection-background-color: {accent_light};
    selection-color: {accent_text};
    border: 1px solid {border};
    outline: none;
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QListWidget, QTreeWidget {{
    border: none;
    border-radius: 8px;
    background: {bg_primary};
    outline: none;
}}
QListView#entryList {{
    border: none;
    border-radius: 8px;
    background: {bg_primary};
    outline: none;
}}
QListWidget::item, QTreeWidget::item {{
    padding: 7px 8px;
    border-bottom: 1px solid {border_light};
}}
QListWidget::item:selected, QTreeWidget::item:selected {{
    background: {item_selected_bg};
    color: {item_selected_text};
}}
QListWidget::item:hover, QTreeWidget::item:hover {{
    background: {item_hover_bg};
}}
QTabWidget::pane {{
    border: 1px solid {border_light};
    border-radius: 8px;
    background: {bg_primary};
}}
QTabBar::tab {{
    padding: 8px 20px;
    border: 1px solid {border_light};
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    background: {btn_bg};
    color: {text_secondary};
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background: {bg_primary};
    color: {accent_text};
    border-bottom: 2px solid {accent};
}}
QGroupBox {{
    border: 1px solid {border_light};
    border-radius: 10px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: bold;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px;
}}
QScrollBar:vertical {{
    border: none;
    background: {scrollbar_bg};
    width: 8px;
}}
QScrollBar::handle:vertical {{
    background: {scrollbar_handle};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {scrollbar_handle_hover};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    border: none;
    background: {scrollbar_bg};
    height: 8px;
}}
QScrollBar::handle:horizontal {{
    background: {scrollbar_handle};
    border-radius: 4px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {scrollbar_handle_hover};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}
QSplitter::handle {{
    background: {divider};
    width: 1px;
}}
QSlider::groove:horizontal {{
    height: 6px;
    background: {border_light};
    border-radius: 3px;
}}
QSlider::handle:horizontal {{
    background: {accent};
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
}}
QSpinBox {{
    border: 1px solid {border};
    border-radius: 8px;
    padding: 4px 8px;
    min-height: 24px;
    background: {bg_input};
    color: {text_primary};
}}
QLabel#sectionLabel {{
    font-size: 14px;
    font-weight: bold;
    color: {accent_text};
}}
QMenuBar {{
    background: {bg_secondary};
    border-bottom: 1px solid {border_light};
    padding: 2px;
}}
QMenuBar::item {{
    padding: 4px 12px;
    border-radius: 4px;
}}
QMenuBar::item:selected {{
    background: {accent_light};
    color: {accent_text};
}}
QMenu {{
    background: {menu_bg};
    border: 1px solid {border};
    border-radius: 10px;
    padding: 4px 0px;
}}
QMenu::item {{
    padding: 6px 28px 6px 20px;
}}
QMenu::item:selected {{
    background: {menu_item_hover};
    border-radius: 4px;
    margin: 0 4px;
    padding: 6px 24px 6px 16px;
}}
QMenu::separator {{
    height: 1px;
    background: {menu_separator};
    margin: 4px 12px;
}}
QStatusBar {{
    background: {bg_secondary};
    border-top: 1px solid {border_light};
    color: {text_secondary};
    font-size: 12px;
    padding: 2px 8px;
}}
QProgressBar {{
    border: 1px solid {border};
    border-radius: 6px;
    background: {progress_bg};
    text-align: center;
    color: {text_primary};
    min-height: 20px;
}}
QProgressBar::chunk {{
    background: {progress_fill};
    border-radius: 3px;
}}
QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 2px solid {border};
    border-radius: 8px;
    background: {bg_input};
}}
QRadioButton::indicator:checked {{
    border-color: {accent};
    background: {accent};
}}
QToolTip {{
    background: {tooltip_bg};
    color: {tooltip_text};
    border: 1px solid {tooltip_border};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}}
QFrame#loginCard {{
    background: {bg_card};
    border: 1px solid {border_light};
    border-radius: 18px;
}}
QWidget#sidebar {{
    background: {sidebar_bg};
    border-right: 1px solid {divider};
}}
QWidget#listPane, QWidget#detailPanel {{
    background: {bg_primary};
}}
QLabel#detailTitle {{
    font-size: 16px;
    font-weight: bold;
    color: {text_primary};
}}
QFrame#detailDivider {{
    background: {divider};
    border: none;
}}
QLabel#detailEmpty {{
    color: {text_muted};
    font-size: 14px;
}}
QLabel#fieldLabel {{
    font-weight: bold;
    color: {text_secondary};
}}
QLabel#fieldValue {{
    color: {text_primary};
}}
QLabel#secretValue {{
    font-family: {font_mono};
    font-size: 13px;
    color: {text_primary};
}}
QLabel#notesValue {{
    color: {text_primary};
    font-size: 13px;
}}
QLabel#metaLabel {{
    color: {text_muted};
    font-size: 12px;
}}
QLabel#detailWarning {{
    background: {danger_light};
    color: {danger};
    border: 1px solid {danger};
    border-radius: 6px;
    padding: 10px;
}}
QLabel#tag {{
    background: {tag_bg};
    color: {tag_text};
    border: 1px solid {tag_border};
    border-radius: 10px;
    font-size: 11px;
    padding: 2px 8px;
}}
QLabel#typeTag {{
    background: {accent_light};
    color: {accent_text};
    border-radius: 10px;
    font-size: 11px;
    padding: 2px 8px;
}}
QFrame#statCard {{
    background: {bg_card};
    border: 1px solid {border_light};
    border-radius: 8px;
    padding: 12px;
}}
QLabel#statCardTitle {{
    font-size: 12px;
    color: {text_secondary};
}}
QPushButton#statActionBtn {{
    border: none;
    background: transparent;
    color: {accent_text};
    font-size: 12px;
    padding: 2px 0;
    text-align: left;
}}
QPushButton#statActionBtn:hover {{
    color: {accent_hover};
}}
QFrame#dupGroup {{
    background: {bg_card};
    border: 1px solid {border_light};
    border-radius: 6px;
    padding: 8px;
}}
QLabel#dupGroupLabel {{
    font-weight: bold;
    font-size: 13px;
    color: {warning_orange};
}}
QWidget#secEntryRow {{
    background: {bg_card};
    border: 1px solid {border_light};
    border-radius: 6px;
}}
QWidget#secEntryRow:hover {{
    background: {bg_card_hover};
}}
QLabel#secRowTitle {{
    font-size: 13px;
    font-weight: bold;
    color: {text_primary};
}}
QLabel#secRowSub {{
    font-size: 11px;
    color: {text_secondary};
}}
QPushButton#secFixBtn {{
    background-color: {accent};
    color: {text_on_accent};
    border: none;
    border-radius: 4px;
    font-size: 12px;
}}
QPushButton#secFixBtn:hover {{
    background-color: {accent_hover};
}}
QLabel#secEmptyHint {{
    color: {text_muted};
    font-size: 14px;
    padding: 32px;
}}
QLabel#secStatusHint {{
    color: {text_muted};
    font-size: 14px;
    padding: 16px;
}}
QLabel#formMessage {{
    font-size: 12px;
    min-height: 18px;
}}
QLabel#formMessage[severity="error"] {{ color: {danger}; }}
QLabel#formMessage[severity="accent"] {{ color: {accent}; }}
QLabel#formMessage[severity="success"] {{ color: {success}; }}
QLabel#formStatus[severity="error"] {{ color: {danger}; }}
QLabel#formStatus[severity="accent"] {{ color: {accent}; }}
QLabel#formStatus[severity="success"] {{ color: {success}; }}
QLabel#formMuted {{
    color: {text_muted};
    font-size: 12px;
}}
QLabel#formMutedSmall {{
    color: {text_muted};
    font-size: 11px;
}}
QLabel#formMutedPlain {{
    color: {text_muted};
}}
QLabel#hintLabel {{
    color: {text_muted};
    font-size: 12px;
}}
"""


def get_style(theme: str) -> str:
    """获取指定主题的样式表。

    Note:
        会调用 set_theme(theme) 设置全局活跃主题作为副作用。
        这是设计上的有意耦合，样式表生成与主题激活必须同步。
    """
    from .constants import FONT_FAMILY_CSS, FONT_FAMILY_MONOSPACE
    from .theme_colors import get_colors, set_theme
    colors = get_colors(theme)
    set_theme(theme)
    return STYLE_TEMPLATE.format(
        font_family=FONT_FAMILY_CSS,
        font_mono=FONT_FAMILY_MONOSPACE,
        **colors,
    )

