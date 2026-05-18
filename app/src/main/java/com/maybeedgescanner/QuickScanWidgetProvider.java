package com.maybeedgescanner;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViews;

public class QuickScanWidgetProvider extends AppWidgetProvider {
    @Override public void onUpdate(Context context, AppWidgetManager manager, int[] appWidgetIds) {
        for (int id : appWidgetIds) {
            Intent intent = new Intent(context, MainActivity.class);
            intent.setAction(MainActivity.ACTION_QUICK_SCAN);
            PendingIntent pending = PendingIntent.getActivity(context, id, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.widget_quick_scan);
            views.setOnClickPendingIntent(R.id.widget_start_scan, pending);
            manager.updateAppWidget(id, views);
        }
    }
}
