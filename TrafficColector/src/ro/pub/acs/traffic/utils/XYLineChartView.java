package ro.pub.acs.traffic.utils;

import net.droidsolutions.droidcharts.awt.Rectangle2D;
import net.droidsolutions.droidcharts.common.HorizontalAlignment;
import net.droidsolutions.droidcharts.core.ChartFactory;
import net.droidsolutions.droidcharts.core.JFreeChart;
import net.droidsolutions.droidcharts.core.axis.NumberAxis;
import net.droidsolutions.droidcharts.core.data.XYDataset;
import net.droidsolutions.droidcharts.core.plot.PlotOrientation;
import net.droidsolutions.droidcharts.core.plot.XYPlot;
import net.droidsolutions.droidcharts.core.renderer.xy.XYLineAndShapeRenderer;
import net.droidsolutions.droidcharts.core.title.LegendTitle;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Handler;
import android.view.View;

public class XYLineChartView extends View
{

	private final String _chartTitle;
	private final String _xLabel;
	private final String _yLabel;
	private final XYDataset _dataSet;

	/** The view bounds. */
	private final Rect mRect = new Rect();

	/** The user interface thread handler. */
	private final Handler mHandler;

	/**
	 * Creates a new graphical view.
	 * 
	 * @param context
	 *          the context
	 * @param chart
	 *          the chart to be drawn
	 */
	public XYLineChartView(Context context, String chartTitle, String xLabel, String yLabel, XYDataset dataSet)
	{
		super(context);
		mHandler = new Handler();
		_chartTitle = chartTitle;
		_xLabel = xLabel;
		_yLabel = yLabel;
		_dataSet = dataSet;
	}

	@Override
	protected void onDraw(Canvas canvas)
	{

		super.onDraw(canvas);
		canvas.getClipBounds(mRect);

		// Get the passed socket_reader data set
		final XYDataset dataset = _dataSet;

		// Create the Chart
		final JFreeChart chart = createChart(dataset);

		// Draw it
		chart.draw(canvas, new Rectangle2D.Double(0, 0, mRect.width(), mRect.height()));
		Paint p = new Paint();
		p.setColor(Color.RED);
	}

	/**
	 * Schedule a user interface repaint.
	 */
	public void repaint()
	{
		mHandler.post(new Runnable()
			{
				public void run()
					{
						invalidate();
					}
			});
	}

	/**
	 * Creates a chart.
	 * 
	 * @param dataset
	 *          the data for the chart.
	 * 
	 * @return a chart.
	 */
	private JFreeChart createChart(final XYDataset dataset)
	{
		// create the chart...
		// (chart title, x-axis label, y-axis label,
		// dataset,orientation,orientation ,url)

		final JFreeChart chart = ChartFactory.createXYLineChart(_chartTitle, _xLabel, _yLabel, dataset, PlotOrientation.VERTICAL, true, true, false);
		
		Paint white = new Paint(Paint.ANTI_ALIAS_FLAG);
		white.setColor(Color.WHITE);

		Paint dkGray = new Paint(Paint.ANTI_ALIAS_FLAG);
		dkGray.setColor(Color.DKGRAY);

		Paint lightGray = new Paint(Paint.ANTI_ALIAS_FLAG);
		lightGray.setColor(Color.LTGRAY);
		lightGray.setStrokeWidth(10);

		// Set Chart Background color
		chart.setBackgroundPaint(white);

		final XYPlot plot = chart.getXYPlot();
		
		LegendTitle legend = chart.getLegend();
		legend.setHorizontalAlignment(HorizontalAlignment.LEFT);
		
		plot.setBackgroundPaint(dkGray);
		plot.setDomainGridlinePaint(lightGray);
		plot.setRangeGridlinePaint(lightGray);

		final XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();
		renderer.setSeriesLinesVisible(0, true);
		plot.setRenderer(renderer);

		// change the auto tick unit selection to integer units only...
		final NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
		rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
		rangeAxis.setLabelAngle(90.0);
		//final NumberAxis domainAxis = (NumberAxis) plot.getDomainAxis();
		return chart;

	}
}
