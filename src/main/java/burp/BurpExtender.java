package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IContextMenuFactory {

    private static final String extensionName = "BurpMenuLevel";
    private static final String menuLevel = "MENU_LEVEL";

    private IBurpExtenderCallbacks callbacks;
    private JMenuBar burpMenuBar;
    private JMenu topMenus;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(extensionName);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);

        // 窗口顶部栏
        burpMenuBar = getBurpFrame().getJMenuBar();
        topMenus = new JMenu("Menu Level");
        JMenuItem level0Menu = new JMenuItem("Name - Scan");
        JMenuItem level1Menu = new JMenuItem("Name -> Scan");
        JMenuItem level2Menu = new JMenuItem("Extensions -> Name - Scan");
        JMenuItem level3Menu = new JMenuItem("Extensions -> Name -> Scan");

        level0Menu.addActionListener(e -> callbacks.saveExtensionSetting(menuLevel, "0"));
        level1Menu.addActionListener(e -> callbacks.saveExtensionSetting(menuLevel, "1"));
        level2Menu.addActionListener(e -> callbacks.saveExtensionSetting(menuLevel, "2"));
        level3Menu.addActionListener(e -> callbacks.saveExtensionSetting(menuLevel, "3"));

        topMenus.add(level0Menu);
        topMenus.add(level1Menu);
        topMenus.add(level2Menu);
        topMenus.add(level3Menu);
        burpMenuBar.add(topMenus);
        burpMenuBar.repaint();

        callbacks.printOutput("Usage: click \"Menu Level\" menu at the top of window to change extension context menu level.");
    }

    @Override
    public void extensionUnloaded() {
        burpMenuBar.remove(topMenus);
        burpMenuBar.repaint();
    }

    private static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>();
        JMenuItem menu = new JMenuItem("flag");
        menus.add(menu);

        String levelStr = callbacks.loadExtensionSetting(menuLevel);
        if (levelStr == null || levelStr.length() == 0) {
            levelStr = "3";
        }

        if (levelStr.equals("3")) {
            return null; // 默认不处理； 返回null，不添加自身插件flag菜单
        }

        changeContextMenuLevel(menus, Integer.parseInt(levelStr));

        return menus;
    }

    /**
     *
     * @param myMenus
     * @param level 可选 0， 1， 2， 3
     */
    private void changeContextMenuLevel(List<JMenuItem> myMenus, int level) {
        if (myMenus.size() == 0) {
            return;
        }

        JMenuItem flagMenu = myMenus.get(0);
        flagMenu.addHierarchyListener(new HierarchyListener() {
            private boolean ran = false;
            @Override
            public void hierarchyChanged(HierarchyEvent e) {
                if ((e.getChangeFlags() & HierarchyEvent.PARENT_CHANGED) != 0) {
                    if (!ran) {
                        ran = true;
                        if (flagMenu.getParent() == null || !(flagMenu.getParent() instanceof JPopupMenu)) {
                            return;
                        }
                        JPopupMenu popupMenu = (JPopupMenu) flagMenu.getParent();
                        Component invoker = popupMenu.getInvoker();


                        if (!(invoker instanceof JMenuItem) || !((JMenuItem) invoker).getText().equals(extensionName)) {
                            return;
                        }
                        JMenuItem extensionNameMenuItem = (JMenuItem)invoker;
                        extensionNameMenuItem.addHierarchyListener(new HierarchyListener() {
                            private boolean ran2 = false;
                            @Override
                            public void hierarchyChanged(HierarchyEvent e) {
                                if ((e.getChangeFlags() & HierarchyEvent.PARENT_CHANGED) != 0) {
                                    if (!ran2) {
                                        ran2 = true;

                                        if (extensionNameMenuItem.getParent() == null || !(extensionNameMenuItem.getParent() instanceof JPopupMenu)) {
                                            return;
                                        }
                                        JPopupMenu extensionsPopupMenu = (JPopupMenu) extensionNameMenuItem.getParent();

                                        if (level == 3) { // Extensions -> Name -> Scan
                                            // 默认不做处理
                                        } else {
                                            Component invoker2 = extensionsPopupMenu.getInvoker();

                                            if (!(invoker2 instanceof JMenuItem) || !((JMenuItem) invoker2).getText().equals("Extensions")) {
                                                return;
                                            }
                                            JMenuItem extensionsMenuItem = (JMenuItem) invoker2;
                                            extensionsMenuItem.addHierarchyListener(new HierarchyListener() {
                                                private boolean ran3 = false;

                                                @Override
                                                public void hierarchyChanged(HierarchyEvent e) {
                                                    if ((e.getChangeFlags() & HierarchyEvent.PARENT_CHANGED) != 0) {
                                                        if (!ran3) {
                                                            ran3 = true;

                                                            if (extensionsMenuItem.getParent() == null || !(extensionsMenuItem.getParent() instanceof JPopupMenu)) {
                                                                return;
                                                            }
                                                            extensionsPopupMenu.remove(extensionNameMenuItem);  // 移除自身插件菜单

                                                            JPopupMenu topLevelPopupMenu = (JPopupMenu) extensionsMenuItem.getParent(); // 拿到 topLevelPopupMenu 就能为所欲为

                                                            // 获取
                                                            List<JMenu> allMenus = new ArrayList<>();
                                                            for (int i = 0; i < extensionsPopupMenu.getComponentCount(); i++ ) {
                                                                JMenu m = (JMenu) extensionsPopupMenu.getComponent(i);
                                                                allMenus.add(m);
                                                            }

                                                            // 移除
                                                            extensionsPopupMenu.removeAll();

                                                            // 添加
                                                            if (level == 2) { // Extensions -> Name - Scan
                                                                for (JMenu menu: allMenus) {
                                                                    List<JMenuItem> items = new ArrayList<>();
                                                                    for (int i = 0; i < menu.getItemCount(); i++) {
                                                                        JMenuItem item = menu.getItem(i);
                                                                        item.setText(menu.getText() + " - " + item.getText());
                                                                        items.add(item);
                                                                    }
                                                                    for (JMenuItem item : items) {
                                                                        extensionsPopupMenu.add(item);
                                                                    }
                                                                }
                                                            } else if (level == 1) { // Name -> Scan
                                                                int index = topLevelPopupMenu.getComponentIndex(extensionsMenuItem) + 1;
                                                                for (int i = 0; i < allMenus.size(); i++) {
                                                                    JMenu menu = allMenus.get(i);
                                                                    topLevelPopupMenu.add(menu, index + i);
                                                                }

                                                                // 隐藏Extensions菜单
                                                                // extensionsMenuItem.setVisible(false);
                                                            } else if (level == 0) { // Name - Scan
                                                                int index = topLevelPopupMenu.getComponentIndex(extensionsMenuItem) + 1;
                                                                int seq = 0;
                                                                for (int i = 0; i < allMenus.size(); i++) {
                                                                    JMenu menu = allMenus.get(i);

                                                                    List<JMenuItem> items = new ArrayList<>();
                                                                    for (int j = 0; j < menu.getItemCount(); j++) {
                                                                        JMenuItem item = menu.getItem(j);
                                                                        item.setText(menu.getText() + " - " + item.getText());
                                                                        items.add(item);
                                                                    }
                                                                    for (JMenuItem item : items) {
                                                                        topLevelPopupMenu.add(item, index + seq);
                                                                        seq += 1;
                                                                    }
                                                                }

                                                            }


                                                        }
                                                    }
                                                }
                                            });
                                        }

                                    }
                                }
                            }
                        });
                    }
                }
            }
        });

    }
}