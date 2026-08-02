"""QSS 样式表 — 颜色/圆角占位符模板与主题渲染。

``STYLE_TEMPLATE`` 以 ``{color_key}`` / ``{radius_*}`` 占位符引用 ``theme_colors`` 的
颜色 token 与 ``radius`` 的圆角档位，同一份模板可渲染浅色/深色两套样式表，避免双主题
样式重复维护。``render_style`` 为纯渲染（不触碰全局活跃主题）；``get_style`` 同样纯
渲染，激活主题由调用方经 ``set_theme`` 显式完成（ARCH-009），保证运行时 ``c()`` 配色
与样式表一致。
"""

STYLE_TEMPLATE = """
QMainWindow, QDialog {{
    background-color: {bg_primary};
}}
QWidget {{
    font-family: {font_family};
    font-size: 14px;
    color: {text_primary};
}}
QScrollArea, QScrollArea > QWidget > QWidget {{
    background: {bg_primary};
    border: none;
}}
QLineEdit, QTextEdit {{
    border: 1px solid {border};
    border-radius: {radius_card}px;
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
    border-radius: {radius_card}px;
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
    border-radius: {radius_pill}px;
    padding: 8px 20px;
    font-weight: 600;
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
    border-radius: {radius_tiny}px;
}}
QDialogButtonBox QPushButton {{
    border-radius: {radius_pill}px;
    padding: 6px 18px;
    min-width: 72px;
}}
QComboBox {{
    border: 1px solid {border};
    border-radius: {radius_card}px;
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
    border-radius: {radius_card}px;
    background: {bg_primary};
    outline: none;
}}
QListView#entryList {{
    border: none;
    border-radius: {radius_card}px;
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
    border-radius: {radius_card}px;
    background: {bg_primary};
}}
QTabBar::tab {{
    padding: 8px 20px;
    border: 1px solid {border_light};
    border-bottom: none;
    border-top-left-radius: {radius_tiny}px;
    border-top-right-radius: {radius_tiny}px;
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
    border-radius: {radius_card}px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: 600;
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
    border-radius: {radius_tiny}px;
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
    border-radius: {radius_tiny}px;
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
    border-radius: {radius_card}px;
    padding: 4px 8px;
    min-height: 24px;
    background: {bg_input};
    color: {text_primary};
}}
QLabel#sectionLabel {{
    font-size: 15px;
    font-weight: 600;
    color: {accent_text};
}}
QLabel#sidebarSectionLabel {{
    font-weight: 600;
    color: {text_secondary};
    font-size: 12px;
    margin-top: 4px;
}}
QLabel#sidebarSeparator {{
    background: {divider};
    margin: 6px 0px;
}}
QLabel#sidebarStatsLabel {{
    color: {text_secondary};
    font-size: 12px;
    margin-top: 4px;
}}
QLabel#sidebarListTitle {{
    font-weight: 600;
    font-size: 15px;
    color: {text_primary};
}}
QLabel#sidebarCountLabel {{
    color: {text_secondary};
    font-size: 12px;
}}
QLabel#sidebarBrandTitle {{
    font-size: 15px;
    font-weight: 600;
    color: {text_primary};
}}
QLabel#sidebarBrandSubtitle {{
    font-size: 11px;
    color: {text_muted};
}}
QLabel#warningText {{
    color: {warning};
    font-size: 12px;
}}
QMenuBar {{
    background: {bg_secondary};
    border-bottom: 1px solid {border_light};
    padding: 2px;
}}
QMenuBar::item {{
    padding: 4px 12px;
    border-radius: {radius_tiny}px;
}}
QMenuBar::item:selected {{
    background: {accent_light};
    color: {accent_text};
}}
QMenu {{
    background: {menu_bg};
    border: 1px solid {border};
    border-radius: {radius_card}px;
    padding: 4px 0px;
}}
QMenu::item {{
    padding: 6px 28px 6px 20px;
}}
QMenu::item:selected {{
    background: {menu_item_hover};
    color: {text_on_accent};
    border-radius: {radius_tiny}px;
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
    border-radius: {radius_small}px;
    background: {progress_bg};
    text-align: center;
    color: {text_primary};
    min-height: 20px;
}}
QProgressBar::chunk {{
    background: {progress_fill};
    border-radius: {radius_tiny}px;
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
    border-radius: {radius_tiny}px;
    padding: 4px 8px;
    font-size: 12px;
}}
QFrame#loginCard {{
    background: {bg_card};
    border: 1px solid {border_light};
    border-radius: {radius_card}px;
}}
QWidget#sidebar {{
    background: {sidebar_bg};
    border-right: 1px solid {divider};
}}
QWidget#listPane, QWidget#detailPanel {{
    background: {bg_primary};
}}
QLabel#detailTitle {{
    font-size: 17px;
    font-weight: 600;
    color: {text_primary};
}}
QFrame#detailDivider {{
    background: {divider};
    border: none;
}}
QLabel#detailEmpty {{
    color: {text_muted};
    font-size: 15px;
}}
QLabel#fieldLabel {{
    font-weight: 600;
    color: {text_secondary};
}}
QLabel#fieldValue {{
    color: {text_primary};
}}
QLabel#secretValue {{
    font-family: {font_mono};
    font-size: 14px;
    color: {text_primary};
}}
QLabel#notesValue {{
    color: {text_primary};
    font-size: 14px;
}}
QLabel#metaLabel {{
    color: {text_muted};
    font-size: 12px;
}}
QLabel#detailWarning {{
    background: {danger_light};
    color: {danger};
    border: 1px solid {danger};
    border-radius: {radius_small}px;
    padding: 10px;
}}
QLabel#tag {{
    background: {tag_bg};
    color: {tag_text};
    border: 1px solid {tag_border};
    border-radius: {radius_tag}px;
    font-size: 11px;
    padding: 2px 8px;
}}
QLabel#typeTag {{
    background: {accent_light};
    color: {accent_text};
    border-radius: {radius_tag}px;
    font-size: 11px;
    padding: 2px 8px;
}}
QFrame#statCard {{
    background: {bg_card};
    border: 1px solid {border_light};
    border-radius: {radius_card}px;
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
    border-radius: {radius_small}px;
    padding: 8px;
}}
QLabel#dupGroupLabel {{
    font-weight: 600;
    font-size: 14px;
    color: {warning_orange};
}}
QWidget#secEntryRow {{
    background: {bg_card};
    border: 1px solid {border_light};
    border-radius: {radius_small}px;
}}
QWidget#secEntryRow:hover {{
    background: {bg_card_hover};
}}
QLabel#secRowTitle {{
    font-size: 14px;
    font-weight: 600;
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
    border-radius: {radius_tiny}px;
    font-size: 12px;
}}
QPushButton#secFixBtn:hover {{
    background-color: {accent_hover};
}}
QLabel#secEmptyHint {{
    color: {text_muted};
    font-size: 15px;
    padding: 32px;
}}
QLabel#secStatusHint {{
    color: {text_muted};
    font-size: 15px;
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


def render_style(theme: str) -> str:
    """纯渲染指定主题的样式表，无副作用。

    仅格式化 ``STYLE_TEMPLATE``，不触碰 ``theme_colors`` 的全局活跃主题；
    调用方自行决定是否经 ``set_theme`` 激活主题（如仅预览样式表时）。
    """
    from .constants import FONT_FAMILY_CSS, FONT_FAMILY_MONOSPACE
    from .radius import RADIUS_CARD, RADIUS_PILL, RADIUS_SMALL, RADIUS_TAG, RADIUS_TINY
    from .theme_colors import get_colors

    colors = get_colors(theme)
    return STYLE_TEMPLATE.format(
        font_family=FONT_FAMILY_CSS,
        font_mono=FONT_FAMILY_MONOSPACE,
        radius_card=RADIUS_CARD,
        radius_small=RADIUS_SMALL,
        radius_tiny=RADIUS_TINY,
        radius_pill=RADIUS_PILL,
        radius_tag=RADIUS_TAG,
        **colors,
    )


def get_style(theme: str) -> str:
    """获取指定主题的样式表（纯渲染，无副作用）。

    样式表生成与全局活跃主题激活解耦，由调用方显式经 ``set_theme(theme)``
    激活（ARCH-009）。调用方须在 ``get_style`` 前或同序列调用 ``set_theme``，
    保证运行时 ``c()`` 配色（delegate 等控件）与样式表一致。
    """
    return render_style(theme)
